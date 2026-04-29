import pytest
from backend.core.snapshot import VersionedSnapshotManager
from pathlib import Path

def test_snapshot_create(tmp_path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("data")
    manager = VersionedSnapshotManager([tmp_path], tmp_path)
    snapshot = manager.create_snapshot(file_path)
    assert snapshot is not None
    assert Path(snapshot["snapshot_path"]).exists()
