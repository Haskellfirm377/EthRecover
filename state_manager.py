"""
state_manager.py — Checkpoint/resume support for EthRecover v2.0.

Allows the user to interrupt a long-running search (Ctrl+C) and resume
later without re-testing candidates that have already been checked.

The checkpoint file stores progress metadata and the original inputs
(corrupted key + targets) so that ``--resume`` works standalone without
requiring the user to re-type the inputs.

Checkpoint format (JSON):
{
    "version": 2,
    "level": 3,
    "completed_batches": [0, 1, 2, ...],
    "total_tested": 123456,
    "max_changes": 3,
    "corrupted_raw": "<original corrupted input>",
    "targets_raw": ["0xABC...", "0xDEF..."],
    "corrupted_hash": "<sha256 of the corrupted input>",
    "targets_hash": "<sha256 of sorted target addresses>",
    "timestamp": "2024-01-01T00:00:00"
}
"""

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Set


@dataclass
class CheckpointState:
    """In-memory representation of recovery progress."""

    version: int = 2
    level: int = 1
    completed_batches: Set[int] = field(default_factory=set)
    total_tested: int = 0
    max_changes: int = 2
    corrupted_raw: str = ""
    targets_raw: List[str] = field(default_factory=list)
    corrupted_hash: str = ""
    targets_hash: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "level": self.level,
            "completed_batches": sorted(self.completed_batches),
            "total_tested": self.total_tested,
            "max_changes": self.max_changes,
            "corrupted_raw": self.corrupted_raw,
            "targets_raw": self.targets_raw,
            "corrupted_hash": self.corrupted_hash,
            "targets_hash": self.targets_hash,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CheckpointState":
        state = cls()
        state.version = d.get("version", 1)
        state.level = d.get("level", 1)
        state.completed_batches = set(d.get("completed_batches", []))
        state.total_tested = d.get("total_tested", 0)
        state.max_changes = d.get("max_changes", 2)
        state.corrupted_raw = d.get("corrupted_raw", "")
        state.targets_raw = d.get("targets_raw", [])
        state.corrupted_hash = d.get("corrupted_hash", "")
        state.targets_hash = d.get("targets_hash", "")
        state.timestamp = d.get("timestamp", "")
        return state


# ---------------------------------------------------------------------------
# Hashing helpers (to verify checkpoint belongs to the same run)
# ---------------------------------------------------------------------------

def _hash_input(corrupted: str) -> str:
    """SHA-256 hex-digest of the corrupted key input."""
    return hashlib.sha256(corrupted.encode("utf-8")).hexdigest()


def _hash_targets(targets: List[str]) -> str:
    """SHA-256 hex-digest of the sorted, lowercased target addresses."""
    combined = ",".join(sorted(t.lower() for t in targets))
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

DEFAULT_CHECKPOINT_FILE = "ethrecover_checkpoint.json"


def save_checkpoint(state: CheckpointState, path: str = DEFAULT_CHECKPOINT_FILE) -> None:
    """
    Atomically save checkpoint state to disk.

    Writes to a temporary file first, then renames — this prevents
    corruption if the process is killed mid-write.
    """
    tmp_path = path + ".tmp"
    data = json.dumps(state.to_dict(), indent=2)

    with open(tmp_path, "w", encoding="utf-8") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())

    os.replace(tmp_path, path)


def load_checkpoint(
    path: str = DEFAULT_CHECKPOINT_FILE,
    corrupted: str = "",
    targets: Optional[List[str]] = None,
) -> Optional[CheckpointState]:
    """
    Load and validate an existing checkpoint.

    Returns None if:
      - The file does not exist.
      - The file is corrupt / unparseable.
      - corrupted/targets are provided AND they don't match the checkpoint.

    When corrupted/targets are empty (standalone --resume), the checkpoint
    is loaded unconditionally and the stored values are used.
    """
    if not os.path.isfile(path):
        return None

    try:
        with open(path, "r", encoding="utf-8") as fh:
            d = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None

    state = CheckpointState.from_dict(d)

    # Validate only if the caller provided values to compare against
    if corrupted:
        if state.corrupted_hash and state.corrupted_hash != _hash_input(corrupted):
            print("  [!] Checkpoint file is for a different corrupted key. Ignoring.")
            return None

    if targets:
        if state.targets_hash and state.targets_hash != _hash_targets(targets):
            print("  [!] Checkpoint file is for different target addresses. Ignoring.")
            return None

    return state


def new_checkpoint(corrupted: str, targets: List[str],
                   max_changes: int) -> CheckpointState:
    """Create a fresh CheckpointState tied to the given inputs."""
    return CheckpointState(
        corrupted_raw=corrupted,
        targets_raw=list(targets),
        corrupted_hash=_hash_input(corrupted),
        targets_hash=_hash_targets(targets),
        max_changes=max_changes,
    )


def clear_checkpoint(path: str = DEFAULT_CHECKPOINT_FILE) -> None:
    """Remove the checkpoint file (called on successful recovery)."""
    try:
        os.remove(path)
    except OSError:
        pass
