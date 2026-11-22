"""Deterministic memory map inspection querying Linux /proc and dpkg file lists."""

import glob
import json
import logging
import os
import re
import time
from pathlib import Path

from .schemas import MemoryCheckResult

logger = logging.getLogger(__name__)

# Root-owned snapshot written by the host-side oakai-memscan service. A rootless pod cannot read
# /proc/<pid>/maps of other users' processes, so this file is the only way to see them.
DEFAULT_MEMMAP_PATH = os.environ.get("OAKAI_MEMMAP_PATH", "/run/oakai/memmap.json")
DEFAULT_MEMMAP_MAX_AGE = int(os.environ.get("OAKAI_MEMMAP_MAX_AGE", "600"))


class MemoryChecker:
    """Inspects Linux /proc/<pid>/maps and dpkg file manifests to verify RAM residency."""

    def __init__(
        self,
        proc_root: str = "/proc",
        dpkg_info_dir: str = "/var/lib/dpkg/info",
        memmap_path: str = DEFAULT_MEMMAP_PATH,
        memmap_max_age: int = DEFAULT_MEMMAP_MAX_AGE,
    ):
        self.proc_root = Path(proc_root)
        self.dpkg_info_dir = Path(dpkg_info_dir)
        self.memmap_path = Path(memmap_path)
        self.memmap_max_age = memmap_max_age

    def _load_snapshot(self) -> dict | None:
        """Load the root memscan snapshot if present, parseable, and fresh; else None."""
        try:
            data = json.loads(self.memmap_path.read_text(encoding="utf-8"))
            age = time.time() - float(data.get("epoch", 0))
            if age > self.memmap_max_age:
                logger.warning(
                    "memscan snapshot is stale (%.0fs old); visibility is partial", age
                )
                return None
            if not isinstance(data.get("files"), dict):
                return None
            return data
        except (OSError, ValueError, TypeError):
            return None

    def _discover_package_files(self, package_name: str) -> list[str]:
        """Resolve actual installed shared libraries and binaries from /var/lib/dpkg/info."""
        clean_pkg = package_name.strip().lower().split(":")[0]
        discovered: set[str] = set()

        if self.dpkg_info_dir.exists() and self.dpkg_info_dir.is_dir():
            pattern_exact = str(self.dpkg_info_dir / f"{clean_pkg}.list")
            pattern_arch = str(self.dpkg_info_dir / f"{clean_pkg}:*.list")
            list_files = glob.glob(pattern_exact) + glob.glob(pattern_arch)

            for list_file in list_files:
                try:
                    with open(list_file, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            path_str = line.strip()
                            if not path_str or "/gconv/" in path_str:
                                continue
                            is_bin = path_str.startswith(
                                ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/")
                            )
                            is_so = path_str.startswith(("/lib/", "/usr/lib/")) and (
                                ".so." in path_str or path_str.endswith(".so")
                            )
                            if is_bin or is_so:
                                basename = os.path.basename(path_str)
                                if len(basename) >= 2:
                                    discovered.add(basename)
                except OSError:
                    continue

        # Heuristic fallback for Debian library naming conventions (e.g., libsystemd0 -> libsystemd.so)
        if not discovered and clean_pkg.startswith("lib"):
            stem = re.sub(r"[0-9.-]+$", "", clean_pkg)
            if len(stem) >= 4:
                discovered.add(f"{stem}.so")

        return sorted(discovered)

    def check_package_in_memory(
        self, package_name: str, candidate_files: list[str] | None = None
    ) -> MemoryCheckResult:
        """Check whether any active process has mapped files related to package_name.

        Searches /proc/<pid>/maps across numeric process directories using resolved
        dpkg shared library and binary manifests.
        """
        if not self.proc_root.exists() or not self.proc_root.is_dir():
            logger.warning("Proc filesystem root %s not accessible", self.proc_root)
            return MemoryCheckResult(in_memory=False, matching_pids=[], mapped_paths=[])

        # Build regex patterns from package name and resolved dpkg files
        patterns: list[re.Pattern] = []
        clean_name = re.escape(package_name.lower().split(":")[0])
        patterns.append(re.compile(rf"\b{clean_name}\b", re.IGNORECASE))

        all_candidates = list(candidate_files or [])
        all_candidates.extend(self._discover_package_files(package_name))

        for file_path in set(all_candidates):
            basename = os.path.basename(file_path)
            if len(basename) >= 2:
                patterns.append(
                    re.compile(rf"(?:^|/){re.escape(basename)}(?:\b|$)", re.IGNORECASE)
                )

        matching_pids: set[int] = set()
        mapped_paths: set[str] = set()

        try:
            entries = os.listdir(self.proc_root)
        except OSError as err:
            logger.error("Failed to read %s: %s", self.proc_root, err)
            return MemoryCheckResult(in_memory=False, matching_pids=[], mapped_paths=[])

        for entry in entries:
            if not entry.isdigit():
                continue

            pid = int(entry)
            maps_file = self.proc_root / entry / "maps"

            if not maps_file.exists():
                continue

            try:
                with open(maps_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line_stripped = line.strip()
                        parts = line_stripped.split(maxsplit=5)
                        if len(parts) >= 6:
                            pathname = parts[5].strip()
                            if pathname and not pathname.startswith("["):
                                for pattern in patterns:
                                    if pattern.search(pathname):
                                        matching_pids.add(pid)
                                        mapped_paths.add(pathname)
                                        break
            except (OSError, PermissionError):
                continue

        # Merge the root-owned host snapshot, which covers processes this pod cannot read
        snapshot = self._load_snapshot()
        visibility = "partial"
        if snapshot is not None:
            visibility = "full"
            for pathname, pids in snapshot["files"].items():
                for pattern in patterns:
                    if pattern.search(pathname):
                        matching_pids.update(int(p) for p in pids)
                        mapped_paths.add(pathname)
                        break

        in_memory = len(matching_pids) > 0
        return MemoryCheckResult(
            in_memory=in_memory,
            matching_pids=sorted(matching_pids),
            mapped_paths=sorted(mapped_paths),
            memory_visibility=visibility,
        )
