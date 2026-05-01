"""Evidence model for DFDOF.

Each file that enters the pipeline is wrapped in an Evidence object so that
hashing, provenance, and derived relationships remain explicit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha1, sha256
from pathlib import Path
from typing import Any


def _utc_now_iso() -> str:
	return datetime.now(timezone.utc).isoformat()


def _hash_file(path: Path) -> tuple[str, str]:
	"""Hash a file in fixed-size chunks to stay memory-safe."""

	sha256_hasher = sha256()
	sha1_hasher = sha1()
	with path.open("rb") as file_handle:
		while True:
			chunk = file_handle.read(64 * 1024)
			if not chunk:
				break
			sha256_hasher.update(chunk)
			sha1_hasher.update(chunk)
	return sha256_hasher.hexdigest(), sha1_hasher.hexdigest()


@dataclass(slots=True)
class Evidence:
	"""A forensically tracked file or derived artefact."""

	path: Path
	provenance: str | None = None
	parent: Evidence | None = None
	source_role: str = "input"
	acquisition_method: str | None = None
	artefact_category: str | None = None
	skip_hash: bool = False
	file_size: int = field(init=False)
	sha256: str = field(init=False)
	sha1: str = field(init=False)
	hash_timestamp: str = field(init=False)
	parent_sha256: str | None = field(init=False, default=None)

	def __post_init__(self) -> None:
		self.path = Path(self.path)
		self.file_size = self.path.stat().st_size
		if self.skip_hash:
			self.sha256 = ""
			self.sha1 = ""
			self.hash_timestamp = ""
		else:
			self.sha256, self.sha1 = _hash_file(self.path)
			self.hash_timestamp = _utc_now_iso()
		self.parent_sha256 = self.parent.sha256 if self.parent is not None else None

	def compute_hash(self) -> None:
		"""Compute hash if it wasn't done during initialization."""
		if not self.sha256:
			self.sha256, self.sha1 = _hash_file(self.path)
			self.hash_timestamp = _utc_now_iso()

	def to_dict(self) -> dict[str, Any]:
		"""Return a JSON-friendly representation of the evidence object."""

		return {
			"path": str(self.path),
			"provenance": self.provenance,
			"parent_sha256": self.parent_sha256,
			"source_role": self.source_role,
			"acquisition_method": self.acquisition_method,
			"artefact_category": self.artefact_category,
			"file_size": self.file_size,
			"sha256": self.sha256,
			"sha1": self.sha1,
			"hash_timestamp": self.hash_timestamp,
		}

	@classmethod
	def from_dict(cls, data: dict[str, Any]) -> Evidence:
		"""Reconstruct an Evidence object without rehashing the file."""

		instance = cls.__new__(cls)
		instance.path = Path(data["path"])
		instance.provenance = data.get("provenance")
		instance.parent = None
		instance.source_role = data.get("source_role", "input")
		instance.acquisition_method = data.get("acquisition_method")
		instance.artefact_category = data.get("artefact_category")
		instance.file_size = int(data.get("file_size", 0))
		instance.sha256 = data["sha256"]
		instance.sha1 = data["sha1"]
		instance.hash_timestamp = data["hash_timestamp"]
		instance.parent_sha256 = data.get("parent_sha256")
		return instance

