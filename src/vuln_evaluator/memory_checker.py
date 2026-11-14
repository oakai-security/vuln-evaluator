"""Deterministic memory map inspection querying Linux /proc filesystem."""

import logging
import os
import re
from pathlib import Path

from .schemas import MemoryCheckResult

logger = logging.getLogger(__name__)


class MemoryChecker:
    """Inspects Linux /proc/<pid>/maps to verify if package libraries are resident in RAM."""

    def __init__(self, proc_root: str = "/proc"):
        self.proc_root = Path(proc_root)

    def check_package_in_memory(
        self, package_name: str, candidate_files: list[str] | None = None
    ) -> MemoryCheckResult:
        """Check whether any active process has mapped files related to package_name.

        Searches /proc/<pid>/maps across numeric process directories.
        """
        if not self.proc_root.exists() or not self.proc_root.is_dir():
            logger.warning("Proc filesystem root %s not accessible", self.proc_root)
            return MemoryCheckResult(in_memory=False, matching_pids=[], mapped_paths=[])

        # Normalize target patterns
        patterns: list[re.Pattern] = []
        clean_name = re.escape(package_name.lower())
        patterns.append(re.compile(rf"\b{clean_name}\b", re.IGNORECASE))

        if candidate_files:
            for file_path in candidate_files:
                basename = os.path.basename(file_path)
                if len(basename) >= 4:
                    patterns.append(re.compile(re.escape(basename), re.IGNORECASE))

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
                        # Memory map format: address perms offset dev inode pathname
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
                # Processes may terminate or require elevated permissions
                continue

        in_memory = len(matching_pids) > 0
        return MemoryCheckResult(
            in_memory=in_memory,
            matching_pids=sorted(matching_pids),
            mapped_paths=sorted(mapped_paths),
        )
