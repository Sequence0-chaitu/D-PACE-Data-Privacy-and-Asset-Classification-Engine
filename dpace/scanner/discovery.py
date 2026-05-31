"""
dpace.scanner.discovery
-----------------------
File Discovery & Reading Module

Walks a target directory, filters files according to policy rules,
and yields (path, content) pairs for the regex engine.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, List

logger = logging.getLogger(__name__)


@dataclass
class FileAsset:
    """Metadata + content for a single discovered file."""

    path: Path
    size_bytes: int
    created_at: datetime | None
    modified_at: datetime | None
    extension: str
    content: str = field(default="", repr=False)

    @property
    def file_name(self) -> str:
        return self.path.name


def _parse_ts(ts: float) -> datetime:
    """Convert a POSIX timestamp to an aware UTC datetime."""
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def discover_files(
    root: str | Path,
    extensions_in_scope: List[str],
    extensions_excluded: List[str],
    max_file_size_mb: int = 100,
    follow_symlinks: bool = False,
    scan_hidden: bool = False,
) -> Generator[FileAsset, None, None]:
    """
    Walk *root* and yield :class:`FileAsset` objects for every file that
    passes the policy filters.

    Parameters
    ----------
    root:
        Top-level directory to scan.
    extensions_in_scope:
        Only files with these extensions will be processed.
        Pass an empty list to scan everything (minus exclusions).
    extensions_excluded:
        File extensions to skip unconditionally.
    max_file_size_mb:
        Files larger than this threshold (in MiB) are skipped.
    follow_symlinks:
        Whether to descend into symbolic links.
    scan_hidden:
        Whether to scan dot-files / dot-directories.
    """
    root = Path(root).expanduser().resolve()
    max_bytes = max_file_size_mb * 1024 * 1024

    if not root.exists():
        raise FileNotFoundError(f"Scan root does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Scan root is not a directory: {root}")

    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        # Prune hidden directories in-place to prevent descent
        if not scan_hidden:
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]

        for fname in filenames:
            if not scan_hidden and fname.startswith("."):
                continue

            fpath = Path(dirpath) / fname
            ext = fpath.suffix.lower()

            if extensions_excluded and ext in extensions_excluded:
                logger.debug("Skipping excluded extension: %s", fpath)
                continue

            if extensions_in_scope and ext not in extensions_in_scope:
                logger.debug("Skipping out-of-scope extension: %s", fpath)
                continue

            try:
                stat = fpath.stat()
            except OSError as exc:
                logger.warning("Cannot stat %s: %s", fpath, exc)
                continue

            if stat.st_size > max_bytes:
                logger.warning(
                    "Skipping oversized file (%.1f MB > %d MB): %s",
                    stat.st_size / (1024 * 1024),
                    max_file_size_mb,
                    fpath,
                )
                continue

            content = _read_file(fpath)
            if content is None:
                continue

            yield FileAsset(
                path=fpath,
                size_bytes=stat.st_size,
                created_at=_parse_ts(stat.st_ctime),
                modified_at=_parse_ts(stat.st_mtime),
                extension=ext,
                content=content,
            )


def _read_file(path: Path, fallback_encoding: str = "latin-1") -> str | None:
    """
    Read a text file, trying UTF-8 first and falling back to *fallback_encoding*.
    Returns *None* if the file cannot be read.
    """
    for enc in ("utf-8", fallback_encoding):
        try:
            return path.read_text(encoding=enc)
        except UnicodeDecodeError:
            continue
        except OSError as exc:
            logger.error("Cannot read %s: %s", path, exc)
            return None
    logger.warning("Could not decode %s with any supported encoding.", path)
    return None
