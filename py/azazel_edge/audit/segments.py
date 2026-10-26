"""Rotated segments of one audit chain (Edge#462 item 1).

A :class:`~azazel_edge.audit.logger.P0AuditLogger` built with ``max_bytes``
rotates its file on a chain boundary: before a record is appended, a file of
``max_bytes`` or more is renamed to ``<name>.1`` (``.1`` to ``.2`` and so on,
up to ``keep``; the oldest is removed) and the record starts a new file. The
chain is not restarted: the new file's first record has ``chain_prev`` = the
last record of the previous file, and carries ``chain_id`` (the chain's
identity, see :func:`chain_id_of`), so a reader that only has the retained
files still knows which chain it is reading.

Readers (the P0 relay's reconcile, the core decision recorder's key window)
read the retained files as one chain with :func:`read_chain`, which takes a
consistent snapshot: every file is opened first, and the snapshot is only
used if no rotation moved a file in between.

Observation only: nothing here decides or enforces.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional

_O_NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)
_O_CLOEXEC = getattr(os, 'O_CLOEXEC', 0)

# Highest rotated suffix a reader probes for (``<name>.1`` .. ``<name>.16``).
MAX_SEGMENTS = 16
# A reader retries a snapshot a rotation moved under it this many times.
SNAPSHOT_ATTEMPTS = 8
# Bound of the first line read to learn the chain's identity.
_HEAD_MAX = 1 << 20


def segment_path(path: str | Path, n: int) -> Path:
    """The ``n``-th rotated file of ``path`` (``n`` >= 1)."""

    p = Path(path)
    return p.with_name(f'{p.name}.{int(n)}')


def chain_id_of(head: Mapping[str, Any]) -> str:
    """Identity of the chain whose oldest retained record is ``head``.

    The genesis record (``chain_prev`` empty) names the chain by its own
    ``chain_hash``. A rotated file's first record carries ``chain_id``. A file
    that starts mid-chain without one (rotated or cut by something else) is
    named by its anchor, the ``chain_prev`` of its first record.
    """

    if not isinstance(head, Mapping):
        return ''
    cid = head.get('chain_id')
    if isinstance(cid, str) and cid:
        return cid
    prev = str(head.get('chain_prev') or '')
    return prev if prev else str(head.get('chain_hash') or '')


def _same_file(path: Path, fd: int) -> bool:
    try:
        st = os.stat(str(path), follow_symlinks=False)
    except OSError:
        return False
    fst = os.fstat(fd)
    return (st.st_dev, st.st_ino) == (fst.st_dev, fst.st_ino)


def _open(path: Path) -> Optional[int]:
    try:
        return os.open(str(path), os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC)
    except FileNotFoundError:
        return None


def _open_snapshot(path: Path) -> tuple:
    """(fds newest first as (path, fd), consistent). The active file first,
    then ``.1``, ``.2``, ... until one is missing."""

    fds: List[tuple] = []
    fd = _open(path)
    if fd is not None:
        fds.append((path, fd))
    n = 1
    while n <= MAX_SEGMENTS:
        p = segment_path(path, n)
        fd = _open(p)
        if fd is None:
            break
        fds.append((p, fd))
        n += 1
    consistent = all(_same_file(p, fd) for p, fd in fds)
    # A rotation in progress can leave a gap (``.1`` renamed to ``.2``
    # before the active file becomes ``.1``): the next one existing means the
    # probe stopped at a gap, not at the end.
    if consistent and n <= MAX_SEGMENTS and os.path.lexists(str(segment_path(path, n + 1))):
        consistent = False
    return fds, consistent


def _pread_all(fd: int, start: int, length: int) -> bytes:
    chunks = []
    offset = start
    remaining = length
    while remaining > 0:
        chunk = os.pread(fd, min(remaining, 1 << 20), offset)
        if not chunk:
            break
        chunks.append(chunk)
        offset += len(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


def _head(fd: int) -> Optional[Dict[str, Any]]:
    data = b''
    step = 1 << 16
    while len(data) < _HEAD_MAX:
        chunk = os.pread(fd, step, len(data))
        if not chunk:
            return None  # no complete first line
        data += chunk
        nl = data.find(b'\n')
        if nl >= 0:
            try:
                row = json.loads(data[:nl])
            except Exception:
                return None
            return row if isinstance(row, dict) else None
    return None


def _last_hash(fd: int, size: int) -> str:
    """chain_hash of the last complete line of a file, '' if unreadable."""

    step = 1 << 16
    data = b''
    pos = size
    while pos > 0 and len(data) < _HEAD_MAX:
        start = max(0, pos - step)
        data = os.pread(fd, pos - start, start) + data
        pos = start
        body = data[:-1] if data.endswith(b'\n') else data
        if b'\n' in body or pos == 0:
            break
        step *= 2
    if not data.endswith(b'\n'):
        # A torn last line: the file's last complete record is before it.
        data = data[:data.rfind(b'\n') + 1] if b'\n' in data else b''
    line = data[:-1].rsplit(b'\n', 1)[-1] if data else b''
    try:
        row = json.loads(line)
    except Exception:
        return ''
    return str(row.get('chain_hash') or '') if isinstance(row, dict) else ''


def _linked(fds: List[tuple]) -> List[tuple]:
    """The files (newest first) that continue one another: a rotated file is
    kept only if the next newer file's first record names its last record as
    ``chain_prev``. A file of the same name that is not part of the chain (a
    host logrotate copy, a leftover) ends the chain there."""

    kept = fds[:1]
    rest = fds[1:]
    if kept and rest and _head(kept[0][1]) is None:
        # The active file has no complete record yet (created by a write
        # that has not finished, or torn by a crash): it cannot be checked,
        # and it does not cut the chain off from the rotated files.
        kept.append(rest[0])
        rest = rest[1:]
    for older in rest:
        newer_head = _head(kept[-1][1])
        if newer_head is None:
            break
        if str(newer_head.get('chain_prev') or '') != _last_hash(older[1], os.fstat(older[1]).st_size):
            break
        kept.append(older)
    return kept


def read_chain(path: str | Path, max_bytes: Optional[int] = None,
               sync: Optional[Callable[[int], bool]] = None) -> Dict[str, Any]:
    """The retained files of one chain, oldest first, as one list of lines.

    Returns ``lines`` (complete lines, oldest first; a last line without its
    newline is left out of every file), ``truncated`` (``max_bytes`` cut the
    oldest part off), ``anchored`` (the oldest retained record is not the
    chain's genesis: earlier records were rotated out), ``chain_id``
    (:func:`chain_id_of` the oldest retained record; '' for an empty chain),
    ``segments`` (files read; a rotated file that does not continue the next
    newer one is not read, ``unlinked_segments`` counts those), ``bytes`` (their total size), ``synced``
    (``sync`` returned True for every file; False when no ``sync``) and
    ``consistent`` (False if a rotation kept moving files for every attempt;
    the last attempt is used).
    """

    base = Path(path)
    fds: List[tuple] = []
    consistent = False
    for attempt in range(SNAPSHOT_ATTEMPTS):
        fds, consistent = _open_snapshot(base)
        if consistent:
            break
        if attempt + 1 < SNAPSHOT_ATTEMPTS:
            for _, fd in fds:
                os.close(fd)
            time.sleep(0.001 * (attempt + 1))
    try:
        linked = _linked(fds)
        oldest_first = list(reversed(linked))
        synced = sync is not None and bool(oldest_first)
        if sync is not None:
            for _, fd in oldest_first:
                synced = bool(sync(fd)) and synced
        sizes = [os.fstat(fd).st_size for _, fd in oldest_first]
        head = _head(oldest_first[0][1]) if oldest_first else None
        budget = None if max_bytes is None else max(0, int(max_bytes))
        parts: List[List[bytes]] = []
        truncated = False
        # Newest first, within the byte budget.
        for idx in range(len(oldest_first) - 1, -1, -1):
            fd = oldest_first[idx][1]
            size = sizes[idx]
            if budget is not None and budget <= 0:
                truncated = True
                break
            take = size if budget is None else min(size, budget)
            start = size - take
            data = _pread_all(fd, start, take)
            if budget is not None:
                budget -= take
            lines = data.split(b'\n')[:-1]
            if start > 0:
                truncated = True
                lines = lines[1:]  # the first line was cut by the window
            parts.append(lines)
        out: List[bytes] = []
        for lines in reversed(parts):
            out.extend(lines)
        return {
            'lines': out,
            'truncated': truncated,
            'anchored': bool(head) and bool(str(head.get('chain_prev') or '')),
            'chain_id': chain_id_of(head) if head else '',
            'segments': len(oldest_first),
            'unlinked_segments': len(fds) - len(linked),
            'bytes': sum(sizes),
            'synced': synced,
            'consistent': consistent,
        }
    finally:
        for _, fd in fds:
            os.close(fd)
