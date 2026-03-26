# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Tests for the migration bundle module."""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from azure_sub_migrator.bundle import (
    BUNDLE_VERSION,
    MAX_BUNDLE_SIZE,
    BundleError,
    create_bundle,
    get_artifact,
    read_bundle,
)

# ──────────────────────────────────────────────────────────────────────
# create_bundle
# ──────────────────────────────────────────────────────────────────────


class TestCreateBundle:
    def test_returns_valid_zip(self, sample_subscription_id, sample_tenant_id):
        data = create_bundle(
            subscription_id=sample_subscription_id,
            source_tenant_id=sample_tenant_id,
            artifacts={"scan_results": {"transfer_safe": [], "requires_action": []}},
        )
        assert isinstance(data, bytes)
        # Should be a valid zip
        buf = io.BytesIO(data)
        with zipfile.ZipFile(buf, "r") as zf:
            assert "manifest.json" in zf.namelist()
            assert "scan_results.json" in zf.namelist()

    def test_manifest_contents(self, sample_subscription_id, sample_tenant_id):
        data = create_bundle(
            subscription_id=sample_subscription_id,
            source_tenant_id=sample_tenant_id,
            artifacts={"scan_results": {"transfer_safe": []}},
        )
        buf = io.BytesIO(data)
        with zipfile.ZipFile(buf, "r") as zf:
            manifest = json.loads(zf.read("manifest.json"))
            assert manifest["bundle_version"] == BUNDLE_VERSION
            assert manifest["subscription_id"] == sample_subscription_id
            assert manifest["source_tenant_id"] == sample_tenant_id
            assert "created_at" in manifest
            assert "scan_results.json" in manifest["files"]
            assert "scan_results.json" in manifest["checksums"]

    def test_includes_multiple_artifacts(self, sample_subscription_id, sample_tenant_id):
        artifacts = {
            "scan_results": {"transfer_safe": []},
            "rbac_assignments": [{"principal_id": "p1", "scope": "/sub/s"}],
            "policy_assignments": [{"name": "pa1"}],
        }
        data = create_bundle(sample_subscription_id, sample_tenant_id, artifacts)
        buf = io.BytesIO(data)
        with zipfile.ZipFile(buf, "r") as zf:
            names = zf.namelist()
            assert "scan_results.json" in names
            assert "rbac_assignments.json" in names
            assert "policy_assignments.json" in names

    def test_skips_unknown_artifacts(self, sample_subscription_id, sample_tenant_id):
        artifacts = {
            "scan_results": {"transfer_safe": []},
            "unknown_thing": {"data": True},
        }
        data = create_bundle(sample_subscription_id, sample_tenant_id, artifacts)
        buf = io.BytesIO(data)
        with zipfile.ZipFile(buf, "r") as zf:
            assert "unknown_thing.json" not in zf.namelist()

    def test_empty_artifacts_still_valid(self, sample_subscription_id, sample_tenant_id):
        data = create_bundle(sample_subscription_id, sample_tenant_id, artifacts={})
        assert isinstance(data, bytes)
        # Should still have manifest
        buf = io.BytesIO(data)
        with zipfile.ZipFile(buf, "r") as zf:
            assert "manifest.json" in zf.namelist()


# ──────────────────────────────────────────────────────────────────────
# read_bundle
# ──────────────────────────────────────────────────────────────────────


class TestReadBundle:
    def _make_bundle(self, artifacts: dict | None = None) -> bytes:
        """Helper to create a valid bundle for testing read_bundle."""
        if artifacts is None:
            artifacts = {"scan_results": {"transfer_safe": []}}
        return create_bundle("sub-1", "tenant-1", artifacts)

    def test_roundtrip(self):
        original_artifacts = {
            "scan_results": {"transfer_safe": [{"name": "r1"}], "requires_action": []},
            "rbac_assignments": [{"principal_id": "p1"}],
        }
        data = self._make_bundle(original_artifacts)
        result = read_bundle(data)

        assert "manifest" in result
        assert "artifacts" in result
        assert result["artifacts"]["scan_results"]["transfer_safe"][0]["name"] == "r1"
        assert result["artifacts"]["rbac_assignments"][0]["principal_id"] == "p1"

    def test_rejects_oversized_bundle(self):
        data = b"x" * (MAX_BUNDLE_SIZE + 1)
        with pytest.raises(BundleError, match="exceeds maximum size"):
            read_bundle(data)

    def test_rejects_invalid_zip(self):
        with pytest.raises(BundleError, match="Not a valid zip"):
            read_bundle(b"not a zip file at all")

    def test_rejects_missing_manifest(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("scan_results.json", json.dumps({"transfer_safe": []}))
        with pytest.raises(BundleError, match="missing manifest"):
            read_bundle(buf.getvalue())

    def test_rejects_missing_required_files(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("manifest.json", json.dumps({
                "bundle_version": 1,
                "files": [],
                "checksums": {},
            }))
        with pytest.raises(BundleError, match="missing required file"):
            read_bundle(buf.getvalue())

    def test_rejects_newer_version(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("manifest.json", json.dumps({
                "bundle_version": BUNDLE_VERSION + 99,
                "files": ["scan_results.json"],
                "checksums": {},
            }))
            zf.writestr("scan_results.json", json.dumps({}))
        with pytest.raises(BundleError, match="newer than supported"):
            read_bundle(buf.getvalue())

    def test_rejects_path_traversal(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("manifest.json", json.dumps({
                "bundle_version": 1,
                "files": [],
                "checksums": {},
            }))
            zf.writestr("../etc/passwd", "bad")
            zf.writestr("scan_results.json", json.dumps({}))
        with pytest.raises(BundleError, match="Invalid path"):
            read_bundle(buf.getvalue())

    def test_rejects_corrupted_checksum(self):
        # Build a valid bundle, then tamper with a file
        buf = io.BytesIO()
        scan_data = json.dumps({"transfer_safe": []}).encode()

        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("manifest.json", json.dumps({
                "bundle_version": 1,
                "files": ["scan_results.json"],
                "checksums": {"scan_results.json": "0000badchecksum"},
            }))
            zf.writestr("scan_results.json", scan_data)

        with pytest.raises(BundleError, match="Checksum mismatch"):
            read_bundle(buf.getvalue())

    def test_ignores_unknown_files(self):
        data = self._make_bundle()
        # Inject an extra file into the zip
        buf = io.BytesIO(data)
        with zipfile.ZipFile(buf, "a") as zf:
            zf.writestr("extra_notes.json", json.dumps({"note": "hello"}))
        result = read_bundle(buf.getvalue())
        assert "extra_notes" not in result["artifacts"]


# ──────────────────────────────────────────────────────────────────────
# get_artifact
# ──────────────────────────────────────────────────────────────────────


class TestGetArtifact:
    def test_returns_artifact(self):
        bundle = {"manifest": {}, "artifacts": {"scan_results": {"data": 1}}}
        assert get_artifact(bundle, "scan_results") == {"data": 1}

    def test_returns_default_when_missing(self):
        bundle = {"manifest": {}, "artifacts": {}}
        assert get_artifact(bundle, "rbac_assignments", []) == []

    def test_returns_none_default(self):
        bundle = {"manifest": {}, "artifacts": {}}
        assert get_artifact(bundle, "rbac_assignments") is None
