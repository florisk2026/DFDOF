"""DFDOF Evidence Management.

Each file that enters the pipeline is wrapped in an `Evidence` object so that
hashing, provenance and derived relationships remain explicit.

Construction contract:
- `source_path` (required): the original forensic identifier for the item
        (file path, archive member name, or similar). This must be provided.
- `stored_path` (optional): path on disk where the evidence is stored. If
        omitted the `source_path` is used as the stored location. The constructor
        will normalise this to a `Path` object.
- `parent` (optional): an `Evidence` instance representing the parent artefact
        (for derived files). If provided, the child's `parent_sha256` will be set to
        the parent's SHA-256 hash to preserve provenance.
- `skip_hash` (optional): when `True` the evidence object will not compute
        file hashes immediately (useful for large files or temporary fixtures). Tests
        and production code should explicitly set `skip_hash=True` only when
        appropriate and later call `compute_hash()` if persistent integrity is
        required.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from hashlib import sha1, sha256
from pathlib import Path
from typing import Any, cast

from config import EVIDENCE_TYPE_INPUT, utc_now_iso


def hash_file(path: Path) -> tuple[str, str]:
    """Hash a file in fixed-size chunks to stay memory-safe."""

    sha256_hasher = sha256()
    sha1_hasher = sha1()
    with path.open("rb") as file_handle:
        while True:
            chunk = file_handle.read(1024 * 1024)
            if not chunk:
                break
            sha256_hasher.update(chunk)
            sha1_hasher.update(chunk)
    return sha256_hasher.hexdigest(), sha1_hasher.hexdigest()


def _path_size(path: Path) -> int:
    """Return byte size for file evidence or recursive content size for directory evidence."""

    if path.is_file():
        return path.stat().st_size
    if path.is_dir():
        total = 0
        for dirpath, _dirnames, filenames in os.walk(path):
            for name in filenames:
                try:
                    total += os.stat(os.path.join(dirpath, name)).st_size
                except OSError:
                    pass
        return total
    return path.stat().st_size


@dataclass
class Evidence:
    """A forensically tracked file or derived artefact."""

    source_path: Path | str
    stored_path: Path | str | None = None
    parent: Evidence | None = None
    acquisition_method: str | None = None
    type: str = EVIDENCE_TYPE_INPUT
    artefact_category: str | None = None
    source_identification: str | None = None
    hash_note: str | None = None
    size: int = field(init=False)
    skip_hash: bool = False
    sha1: str = field(init=False)
    sha256: str = field(init=False)
    hash_timestamp: str = field(init=False)
    parent_sha256: str | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        if self.source_path is None:
            raise ValueError("source_path is required for Evidence")
        if self.stored_path is None:
            stored_path = Path(self.source_path)
        else:
            stored_path = Path(self.stored_path)
        self.stored_path = stored_path
        self.size = _path_size(stored_path)
        if self.skip_hash:
            self.sha1 = ""
            self.sha256 = ""
            self.hash_timestamp = ""
        else:
            self.sha256, self.sha1 = hash_file(stored_path)
            self.hash_timestamp = utc_now_iso()
        self.parent_sha256 = self.parent.sha256 if self.parent is not None else None
        if self.source_identification is None and self.parent is not None:
            self.source_identification = self.parent.source_identification

    def compute_hash(self) -> None:
        """Compute hash if it wasn't done during initialization."""
        if not self.sha256:
            self.sha256, self.sha1 = hash_file(cast(Path, self.stored_path))
            self.hash_timestamp = utc_now_iso()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation of the evidence object."""

        stored_path = cast(Path, self.stored_path)
        result = {
            "source_path": str(self.source_path),
            "stored_path": str(stored_path),
            "source_identification": self.source_identification,
            "parent_sha256": (self.parent_sha256 if self.parent_sha256 else None),
            "acquisition_method": self.acquisition_method,
            "type": self.type,
            "artefact_category": self.artefact_category,
            "size": self.size,
            "sha1": (self.sha1 if self.sha1 else None),
            "sha256": (self.sha256 if self.sha256 else None),
            "hash_timestamp": (self.hash_timestamp if self.hash_timestamp else None),
        }
        if self.hash_note:
            result["hash_note"] = self.hash_note
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Evidence:
        """Reconstruct an Evidence object without rehashing the file."""

        instance = cls.__new__(cls)
        instance.source_path = data["source_path"]
        instance.parent = None
        instance.source_identification = data.get("source_identification")
        instance.acquisition_method = data.get("acquisition_method")
        instance.type = data.get("type", EVIDENCE_TYPE_INPUT)
        instance.artefact_category = data.get("artefact_category")
        instance.size = int(data["size"])
        instance.sha1 = data.get("sha1") or ""
        instance.sha256 = data.get("sha256") or ""
        instance.hash_timestamp = data.get("hash_timestamp") or ""
        instance.hash_note = data.get("hash_note") or None
        raw_stored_path = data.get("stored_path")
        if raw_stored_path is not None:
            instance.stored_path = Path(raw_stored_path)
        else:
            instance.stored_path = Path(instance.source_path)
        instance.parent_sha256 = data.get("parent_sha256")
        return instance


def make_evidence(
    *,
    source_path: str | Path,
    stored_path: Path,
    parent: "Evidence | None",
    acquisition_method: str,
    type: str,
    artefact_category: str | None = None,
    source_identification: str | None = None,
    skip_hash: bool = False,
    hash_note: str | None = None,
) -> "Evidence":
    """Factory: construct and return a fully attributed Evidence object."""
    evidence = Evidence(
        source_path=source_path,
        stored_path=stored_path,
        parent=parent,
        acquisition_method=acquisition_method,
        type=type,
        artefact_category=artefact_category,
        source_identification=source_identification,
        skip_hash=skip_hash,
        hash_note=hash_note,
    )
    return evidence
