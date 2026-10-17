import argparse
import errno
import json
import os
import platform
import posixpath
import shutil
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path

import octopage

VERSION = "0.2.0"
PAGE_SIZE = 4096
BUDGET_SOFT_BYTES = 800 * 1024 * 1024  # 800 MB soft limit (Section 2.1 / 13.1)
MAX_FILE_SIZE = 256 * 1024 * 1024      # 256 MiB max_file_size (Section 2.1)
ROOT_INO = 1

SCHEMA_SQL = """
BEGIN;
CREATE TABLE IF NOT EXISTS inode (
    ino INTEGER PRIMARY KEY,
    mode INTEGER NOT NULL,
    nlink INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    gid INTEGER NOT NULL,
    size INTEGER NOT NULL,
    blocks INTEGER NOT NULL,
    atime REAL NOT NULL,
    mtime REAL NOT NULL,
    ctime REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS dirent (
    parent INTEGER NOT NULL,
    name TEXT NOT NULL,
    ino INTEGER NOT NULL,
    PRIMARY KEY (parent, name)
);
CREATE TABLE IF NOT EXISTS chunk (
    ino INTEGER NOT NULL,
    page_idx INTEGER NOT NULL,
    data BLOB NOT NULL,
    PRIMARY KEY (ino, page_idx)
);
COMMIT;
"""

# Optional FUSE import so `selftest` and `bench` work even if WinFsp/fusepy isn't loaded yet
try:
    from fuse import FUSE, FuseOSError, Operations
except ImportError:
    FUSE = None

    class Operations:  # type: ignore
        pass

    class FuseOSError(OSError):  # type: ignore
        def __init__(self, err):
            super().__init__(err, os.strerror(err))
            self.errno = err


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def summarize(values):
    s = sorted(values)
    n = len(s)
    if not n:
        return None

    def q(p):
        k = (n - 1) * p
        f = int(k)
        c = min(f + 1, n - 1)
        return s[f] + (s[c] - s[f]) * (k - f)

    return {
        "n": n,
        "p50": round(q(0.5), 2),
        "p95": round(q(0.95), 2),
        "min": round(s[0], 2),
        "max": round(s[-1], 2),
        "mean": round(sum(s) / n, 2),
    }


class OctoBlockSpikeFS(Operations):
    """
    Phase A throwaway prototype on octopage-python (Section 3.2 & 20).
    Uses inode numbers and 4 KB chunked content with group commit.
    """

    def __init__(
        self,
        location: str,
        token: str | None = None,
        branch: str = "main",
        mode: str = "balanced",
        flush_interval: float | None = None,
        flush_bytes: int = 8 * 1024 * 1024,
        cache_dir: str | None = None,
    ):
        self.location = location
        self.mode = mode
        if flush_interval is not None:
            self.flush_interval = flush_interval
        else:
            self.flush_interval = 60.0 if mode == "relaxed" else 5.0
        self.flush_bytes = flush_bytes

        self.lock = threading.RLock()
        self.conn = octopage.connect(
            location,
            token=token,
            branch=branch,
            create=True,
            cache_dir=cache_dir,
            autocommit=False,
        )
        self.dirty_bytes = 0
        self.dirty_ops = 0
        self.group_started_at: float | None = None
        self.commits = 0
        self._next_fh = 1
        self._init_schema()

    def _init_schema(self) -> None:
        with self.lock:
            self.conn.executescript(SCHEMA_SQL)
            cur = self.conn.execute("SELECT count(*) FROM inode WHERE ino = ?", (ROOT_INO,))
            row = cur.fetchone()
            if not row or row[0] == 0:
                now = time.time()
                self.conn.execute(
                    "INSERT INTO inode (ino, mode, nlink, uid, gid, size, blocks, atime, mtime, ctime) "
                    "VALUES (?, ?, 2, 1000, 1000, 0, 0, ?, ?, ?)",
                    (ROOT_INO, stat.S_IFDIR | 0o755, now, now, now),
                )
                self.conn.commit()
                self.commits += 1

    def close(self) -> None:
        with self.lock:
            self.flush_group(force=True)
            self.conn.close()

    # ------------------------------------------------------------------ group commit engine

    def _record_mutation(self, nbytes: int = 0) -> None:
        if self.group_started_at is None:
            self.group_started_at = time.perf_counter()
        self.dirty_ops += 1
        self.dirty_bytes += nbytes
        elapsed = time.perf_counter() - self.group_started_at
        if self.dirty_bytes >= self.flush_bytes or elapsed >= self.flush_interval or self.dirty_ops >= 50_000:
            self.flush_group(force=True)

    def flush_group(self, force: bool = False) -> bool:
        """Commit open group to OctoPage (L2 commit). Empty groups are never pushed (REQ-11)."""
        with self.lock:
            if self.dirty_ops == 0 and not self.conn.in_transaction:
                return False
            if not force and self.group_started_at is not None:
                elapsed = time.perf_counter() - self.group_started_at
                if elapsed < self.flush_interval and self.dirty_bytes < self.flush_bytes:
                    return False
            self.conn.commit()
            self.dirty_bytes = 0
            self.dirty_ops = 0
            self.group_started_at = None
            self.commits += 1
            return True

    # ------------------------------------------------------------------ path & inode resolution

    def _split_path(self, path: str) -> list[str]:
        norm = path.replace("\\", "/")
        parts = [p for p in norm.split("/") if p]
        for p in parts:
            if len(p.encode("utf-8", "surrogateescape")) > 255:
                raise FuseOSError(errno.ENAMETOOLONG)
        if len(norm.encode("utf-8", "surrogateescape")) > 4096:
            raise FuseOSError(errno.ENAMETOOLONG)
        return parts

    def _resolve_path(self, path: str) -> int | None:
        parts = self._split_path(path)
        curr = ROOT_INO
        for part in parts:
            row = self.conn.execute(
                "SELECT ino FROM dirent WHERE parent = ? AND name = ?",
                (curr, part),
            ).fetchone()
            if row is None:
                return None
            curr = row[0]
        return curr

    def _resolve_parent(self, path: str) -> tuple[int, str]:
        norm = path.replace("\\", "/").rstrip("/")
        if not norm or norm == "/":
            raise FuseOSError(errno.EINVAL)
        parent_path, name = posixpath.split(norm)
        if not name or name in (".", ".."):
            raise FuseOSError(errno.EINVAL)
        if len(name.encode("utf-8", "surrogateescape")) > 255:
            raise FuseOSError(errno.ENAMETOOLONG)
        parent_ino = self._resolve_path(parent_path or "/")
        if parent_ino is None:
            raise FuseOSError(errno.ENOENT)
        parent_row = self.conn.execute("SELECT mode FROM inode WHERE ino = ?", (parent_ino,)).fetchone()
        if not parent_row or not stat.S_ISDIR(parent_row[0]):
            raise FuseOSError(errno.ENOTDIR)
        return parent_ino, name

    # ------------------------------------------------------------------ POSIX FUSE operations

    def getattr(self, path, fh=None):
        with self.lock:
            ino = self._resolve_path(path)
            if ino is None:
                raise FuseOSError(errno.ENOENT)
            row = self.conn.execute(
                "SELECT mode, nlink, uid, gid, size, blocks, atime, mtime, ctime FROM inode WHERE ino = ?",
                (ino,),
            ).fetchone()
            if row is None:
                raise FuseOSError(errno.ENOENT)
            mode, nlink, uid, gid, size, blocks, atime, mtime, ctime = row
            return {
                "st_ino": ino,
                "st_mode": mode,
                "st_nlink": nlink,
                "st_uid": uid,
                "st_gid": gid,
                "st_size": size,
                "st_blocks": (blocks * PAGE_SIZE) // 512,
                "st_blksize": PAGE_SIZE,
                "st_atime": atime,
                "st_mtime": mtime,
                "st_ctime": ctime,
            }

    def readdir(self, path, fh):
        with self.lock:
            ino = self._resolve_path(path)
            if ino is None:
                raise FuseOSError(errno.ENOENT)
            rows = self.conn.execute(
                "SELECT name FROM dirent WHERE parent = ? ORDER BY name",
                (ino,),
            ).fetchall()
            return [".", ".."] + [r[0] for r in rows]

    def mkdir(self, path, mode):
        with self.lock:
            parent_ino, name = self._resolve_parent(path)
            existing = self.conn.execute(
                "SELECT ino FROM dirent WHERE parent = ? AND name = ?",
                (parent_ino, name),
            ).fetchone()
            if existing is not None:
                raise FuseOSError(errno.EEXIST)
            now = time.time()
            cur = self.conn.execute(
                "INSERT INTO inode (mode, nlink, uid, gid, size, blocks, atime, mtime, ctime) "
                "VALUES (?, 2, 1000, 1000, 0, 0, ?, ?, ?)",
                (stat.S_IFDIR | (mode & 0o7777), now, now, now),
            )
            ino = cur.lastrowid
            self.conn.execute(
                "INSERT INTO dirent (parent, name, ino) VALUES (?, ?, ?)",
                (parent_ino, name, ino),
            )
            self.conn.execute(
                "UPDATE inode SET nlink = nlink + 1, mtime = ?, ctime = ? WHERE ino = ?",
                (now, now, parent_ino),
            )
            self._record_mutation(128)
            return 0

    def rmdir(self, path):
        with self.lock:
            parent_ino, name = self._resolve_parent(path)
            row = self.conn.execute(
                "SELECT ino FROM dirent WHERE parent = ? AND name = ?",
                (parent_ino, name),
            ).fetchone()
            if row is None:
                raise FuseOSError(errno.ENOENT)
            ino = row[0]
            mode_row = self.conn.execute("SELECT mode FROM inode WHERE ino = ?", (ino,)).fetchone()
            if not mode_row or not stat.S_ISDIR(mode_row[0]):
                raise FuseOSError(errno.ENOTDIR)
            child = self.conn.execute("SELECT 1 FROM dirent WHERE parent = ? LIMIT 1", (ino,)).fetchone()
            if child is not None:
                raise FuseOSError(errno.ENOTEMPTY)
            now = time.time()
            self.conn.execute("DELETE FROM dirent WHERE parent = ? AND name = ?", (parent_ino, name))
            self.conn.execute("DELETE FROM inode WHERE ino = ?", (ino,))
            self.conn.execute(
                "UPDATE inode SET nlink = MAX(2, nlink - 1), mtime = ?, ctime = ? WHERE ino = ?",
                (now, now, parent_ino),
            )
            self._record_mutation(64)
            return 0

    def create(self, path, mode, fi=None):
        with self.lock:
            parent_ino, name = self._resolve_parent(path)
            existing = self.conn.execute(
                "SELECT ino FROM dirent WHERE parent = ? AND name = ?",
                (parent_ino, name),
            ).fetchone()
            now = time.time()
            if existing is not None:
                ino = existing[0]
                self.conn.execute("DELETE FROM chunk WHERE ino = ?", (ino,))
                self.conn.execute(
                    "UPDATE inode SET size = 0, blocks = 0, mtime = ?, ctime = ? WHERE ino = ?",
                    (now, now, ino),
                )
            else:
                cur = self.conn.execute(
                    "INSERT INTO inode (mode, nlink, uid, gid, size, blocks, atime, mtime, ctime) "
                    "VALUES (?, 1, 1000, 1000, 0, 0, ?, ?, ?)",
                    (stat.S_IFREG | (mode & 0o7777), now, now, now),
                )
                ino = cur.lastrowid
                self.conn.execute(
                    "INSERT INTO dirent (parent, name, ino) VALUES (?, ?, ?)",
                    (parent_ino, name, ino),
                )
                self.conn.execute(
                    "UPDATE inode SET mtime = ?, ctime = ? WHERE ino = ?",
                    (now, now, parent_ino),
                )
            self._record_mutation(128)
            self._next_fh += 1
            return self._next_fh

    def open(self, path, flags):
        with self.lock:
            ino = self._resolve_path(path)
            if ino is None:
                raise FuseOSError(errno.ENOENT)
            if flags & os.O_TRUNC:
                self.truncate(path, 0)
            self._next_fh += 1
            return self._next_fh

    def read(self, path, size, offset, fh):
        with self.lock:
            ino = self._resolve_path(path)
            if ino is None:
                raise FuseOSError(errno.ENOENT)
            row = self.conn.execute("SELECT size FROM inode WHERE ino = ?", (ino,)).fetchone()
            if row is None:
                raise FuseOSError(errno.ENOENT)
            file_size = row[0]
            if offset >= file_size or size <= 0:
                return b""
            size = min(size, file_size - offset)

            start_page = offset // PAGE_SIZE
            end_page = (offset + size - 1) // PAGE_SIZE
            rows = self.conn.execute(
                "SELECT page_idx, data FROM chunk WHERE ino = ? AND page_idx BETWEEN ? AND ?",
                (ino, start_page, end_page),
            ).fetchall()
            page_map = {r[0]: r[1] for r in rows}

            buf = bytearray()
            for p_idx in range(start_page, end_page + 1):
                chunk = page_map.get(p_idx)
                if chunk is None:
                    buf.extend(b"\x00" * PAGE_SIZE)
                elif len(chunk) < PAGE_SIZE:
                    buf.extend(chunk + b"\x00" * (PAGE_SIZE - len(chunk)))
                else:
                    buf.extend(chunk[:PAGE_SIZE])

            rel = offset - (start_page * PAGE_SIZE)
            return bytes(buf[rel : rel + size])

    def write(self, path, data, offset, fh):
        if isinstance(data, memoryview):
            data = data.tobytes()
        n = len(data)
        if n == 0:
            return 0
        if offset + n > MAX_FILE_SIZE:
            raise FuseOSError(errno.EFBIG)

        with self.lock:
            ino = self._resolve_path(path)
            if ino is None:
                raise FuseOSError(errno.ENOENT)
            row = self.conn.execute("SELECT size FROM inode WHERE ino = ?", (ino,)).fetchone()
            if row is None:
                raise FuseOSError(errno.ENOENT)

            start_page = offset // PAGE_SIZE
            end_page = (offset + n - 1) // PAGE_SIZE

            # Fetch existing pages for partial-page Read-Modify-Write (Section 3.5)
            existing = {}
            for p_idx in (start_page, end_page):
                r = self.conn.execute(
                    "SELECT data FROM chunk WHERE ino = ? AND page_idx = ?",
                    (ino, p_idx),
                ).fetchone()
                if r is not None:
                    existing[p_idx] = r[0]

            pos = 0
            for p_idx in range(start_page, end_page + 1):
                page_off = (offset - p_idx * PAGE_SIZE) if p_idx == start_page else 0
                take = min(PAGE_SIZE - page_off, n - pos)
                slice_bytes = data[pos : pos + take]
                pos += take

                if page_off == 0 and take == PAGE_SIZE:
                    page_data = slice_bytes
                else:
                    base = bytearray(existing.get(p_idx, b"\x00" * PAGE_SIZE))
                    if len(base) < PAGE_SIZE:
                        base.extend(b"\x00" * (PAGE_SIZE - len(base)))
                    base[page_off : page_off + take] = slice_bytes
                    page_data = bytes(base)

                self.conn.execute(
                    "INSERT OR REPLACE INTO chunk (ino, page_idx, data) VALUES (?, ?, ?)",
                    (ino, p_idx, page_data),
                )

            new_size = max(row[0], offset + n)
            blocks = self.conn.execute(
                "SELECT count(*) FROM chunk WHERE ino = ?", (ino,)
            ).fetchone()[0]
            now = time.time()
            self.conn.execute(
                "UPDATE inode SET size = ?, blocks = ?, mtime = ?, ctime = ? WHERE ino = ?",
                (new_size, blocks, now, now, ino),
            )
            self._record_mutation(n)
            return n

    def truncate(self, path, length, fh=None):
        if length < 0:
            raise FuseOSError(errno.EINVAL)
        if length > MAX_FILE_SIZE:
            raise FuseOSError(errno.EFBIG)
        with self.lock:
            ino = self._resolve_path(path)
            if ino is None:
                raise FuseOSError(errno.ENOENT)
            last_keep_page = (length - 1) // PAGE_SIZE if length > 0 else -1
            self.conn.execute(
                "DELETE FROM chunk WHERE ino = ? AND page_idx > ?",
                (ino, last_keep_page),
            )
            # Zero tail bytes of the cut page so later extensions read as zeroes (EC-Z06)
            if length > 0 and (length % PAGE_SIZE) != 0:
                tail_off = length % PAGE_SIZE
                row = self.conn.execute(
                    "SELECT data FROM chunk WHERE ino = ? AND page_idx = ?",
                    (ino, last_keep_page),
                ).fetchone()
                if row is not None:
                    buf = bytearray(row[0])
                    if len(buf) < PAGE_SIZE:
                        buf.extend(b"\x00" * (PAGE_SIZE - len(buf)))
                    buf[tail_off:] = b"\x00" * (PAGE_SIZE - tail_off)
                    self.conn.execute(
                        "INSERT OR REPLACE INTO chunk (ino, page_idx, data) VALUES (?, ?, ?)",
                        (ino, last_keep_page, bytes(buf)),
                    )
            blocks = self.conn.execute(
                "SELECT count(*) FROM chunk WHERE ino = ?", (ino,)
            ).fetchone()[0]
            now = time.time()
            self.conn.execute(
                "UPDATE inode SET size = ?, blocks = ?, mtime = ?, ctime = ? WHERE ino = ?",
                (length, blocks, now, now, ino),
            )
            self._record_mutation(64)
            return 0

    def unlink(self, path):
        with self.lock:
            parent_ino, name = self._resolve_parent(path)
            row = self.conn.execute(
                "SELECT ino FROM dirent WHERE parent = ? AND name = ?",
                (parent_ino, name),
            ).fetchone()
            if row is None:
                raise FuseOSError(errno.ENOENT)
            ino = row[0]
            mode_row = self.conn.execute(
                "SELECT mode, nlink FROM inode WHERE ino = ?", (ino,)
            ).fetchone()
            if mode_row and stat.S_ISDIR(mode_row[0]):
                raise FuseOSError(errno.EISDIR)
            now = time.time()
            self.conn.execute("DELETE FROM dirent WHERE parent = ? AND name = ?", (parent_ino, name))
            if mode_row and mode_row[1] > 1:
                self.conn.execute(
                    "UPDATE inode SET nlink = nlink - 1, ctime = ? WHERE ino = ?",
                    (now, ino),
                )
            else:
                self.conn.execute("DELETE FROM chunk WHERE ino = ?", (ino,))
                self.conn.execute("DELETE FROM inode WHERE ino = ?", (ino,))
            self.conn.execute(
                "UPDATE inode SET mtime = ?, ctime = ? WHERE ino = ?",
                (now, now, parent_ino),
            )
            self._record_mutation(64)
            return 0

    def rename(self, old, new):
        with self.lock:
            old_parent, old_name = self._resolve_parent(old)
            new_parent, new_name = self._resolve_parent(new)
            src_row = self.conn.execute(
                "SELECT ino FROM dirent WHERE parent = ? AND name = ?",
                (old_parent, old_name),
            ).fetchone()
            if src_row is None:
                raise FuseOSError(errno.ENOENT)
            src_ino = src_row[0]
            if old_parent == new_parent and old_name == new_name:
                return 0

            # Prevent moving a directory into its own descendant (EC-N10)
            src_mode = self.conn.execute("SELECT mode FROM inode WHERE ino = ?", (src_ino,)).fetchone()[0]
            if stat.S_ISDIR(src_mode):
                curr = new_parent
                while curr != ROOT_INO:
                    if curr == src_ino:
                        raise FuseOSError(errno.EINVAL)
                    p = self.conn.execute("SELECT parent FROM dirent WHERE ino = ?", (curr,)).fetchone()
                    if not p:
                        break
                    curr = p[0]

            dst_row = self.conn.execute(
                "SELECT ino FROM dirent WHERE parent = ? AND name = ?",
                (new_parent, new_name),
            ).fetchone()
            now = time.time()
            if dst_row is not None:
                dst_ino = dst_row[0]
                dst_mode = self.conn.execute("SELECT mode FROM inode WHERE ino = ?", (dst_ino,)).fetchone()[0]
                if stat.S_ISDIR(src_mode) and not stat.S_ISDIR(dst_mode):
                    raise FuseOSError(errno.ENOTDIR)
                if not stat.S_ISDIR(src_mode) and stat.S_ISDIR(dst_mode):
                    raise FuseOSError(errno.EISDIR)
                if stat.S_ISDIR(dst_mode):
                    has_child = self.conn.execute(
                        "SELECT 1 FROM dirent WHERE parent = ? LIMIT 1", (dst_ino,)
                    ).fetchone()
                    if has_child:
                        raise FuseOSError(errno.ENOTEMPTY)
                self.conn.execute("DELETE FROM dirent WHERE parent = ? AND name = ?", (new_parent, new_name))
                self.conn.execute("DELETE FROM chunk WHERE ino = ?", (dst_ino,))
                self.conn.execute("DELETE FROM inode WHERE ino = ?", (dst_ino,))

            self.conn.execute("DELETE FROM dirent WHERE parent = ? AND name = ?", (old_parent, old_name))
            self.conn.execute(
                "INSERT INTO dirent (parent, name, ino) VALUES (?, ?, ?)",
                (new_parent, new_name, src_ino),
            )
            self.conn.execute(
                "UPDATE inode SET mtime = ?, ctime = ? WHERE ino IN (?, ?)",
                (now, now, old_parent, new_parent),
            )
            self._record_mutation(128)
            return 0

    def chmod(self, path, mode):
        with self.lock:
            ino = self._resolve_path(path)
            if ino is None:
                raise FuseOSError(errno.ENOENT)
            old_mode = self.conn.execute("SELECT mode FROM inode WHERE ino = ?", (ino,)).fetchone()[0]
            new_mode = stat.S_IFMT(old_mode) | (mode & 0o7777)
            self.conn.execute(
                "UPDATE inode SET mode = ?, ctime = ? WHERE ino = ?",
                (new_mode, time.time(), ino),
            )
            self._record_mutation(32)
            return 0

    def utimens(self, path, times=None):
        with self.lock:
            ino = self._resolve_path(path)
            if ino is None:
                raise FuseOSError(errno.ENOENT)
            now = time.time()
            atime, mtime = times if times else (now, now)
            self.conn.execute(
                "UPDATE inode SET atime = ?, mtime = ?, ctime = ? WHERE ino = ?",
                (atime, mtime, now, ino),
            )
            self._record_mutation(32)
            return 0

    def fsync(self, path, datasync, fh):
        # Section 6.6: strict mode forces an L2 group commit; balanced/relaxed checks timer
        with self.lock:
            if self.mode == "strict":
                self.flush_group(force=True)
            else:
                self.flush_group(force=False)
            return 0

    def flush(self, path, fh):
        with self.lock:
            self.flush_group(force=False)
            return 0

    def release(self, path, fh):
        return 0

    def statfs(self, path):
        # Section 8 & 13.1: report the 800 MB volume budget and live blocks
        with self.lock:
            used_pages = self.conn.execute(
                "SELECT COALESCE(SUM(blocks), 0) FROM inode"
            ).fetchone()[0]
            total_pages = BUDGET_SOFT_BYTES // PAGE_SIZE
            free_pages = max(0, total_pages - used_pages)
            return {
                "f_bsize": PAGE_SIZE,
                "f_frsize": PAGE_SIZE,
                "f_blocks": total_pages,
                "f_bfree": free_pages,
                "f_bavail": free_pages,
                "f_namemax": 255,
            }


# ------------------------------------------------------------------ Phase A Measurement Suite

def run_phase_a_benchmarks(location: str, token: str | None = None, scale: float = 1.0) -> dict:
    """Measure Phase A operations against Section 10.3 targets."""
    n_fast = max(5, round(40 * scale))
    n_push = max(2, round(10 * scale))
    cases: dict[str, list[float]] = {}
    checks: dict[str, bool] = {}

    def record(name: str, ms: float):
        cases.setdefault(name, []).append(round(ms, 3))

    fs = OctoBlockSpikeFS(location, token=token, mode="balanced", flush_interval=300.0)
    try:
        # 1. Small file create + 1 KB write (L0 in-memory op, target < 1 ms)
        fs.mkdir("/work", 0o755)
        payload_1k = os.urandom(1024)
        for i in range(n_fast):
            p = f"/work/small_{i}.txt"
            t0 = time.perf_counter()
            fh = fs.create(p, 0o644)
            fs.write(p, payload_1k, 0, fh)
            record("create+write/1kb-L0", (time.perf_counter() - t0) * 1000)

        # 2. Warm stat through daemon (target < 0.2 ms)
        for i in range(n_fast):
            p = f"/work/small_{i}.txt"
            t0 = time.perf_counter()
            st = fs.getattr(p)
            record("stat/warm-daemon", (time.perf_counter() - t0) * 1000)
            if i == 0:
                checks["stat/returns-1024-bytes"] = st["st_size"] == 1024

        # 3. Warm read 4 KB file (target < 1 ms)
        payload_4k = os.urandom(PAGE_SIZE)
        fh = fs.create("/work/read4k.bin", 0o644)
        fs.write("/work/read4k.bin", payload_4k, 0, fh)
        for _ in range(n_fast):
            t0 = time.perf_counter()
            got = fs.read("/work/read4k.bin", PAGE_SIZE, 0, fh)
            record("read/warm-4kb", (time.perf_counter() - t0) * 1000)
        checks["read/4kb-matches-exact-bytes"] = got == payload_4k

        # 4. Partial-page Read-Modify-Write across page boundary (EC-Z04, EC-Z06)
        fh = fs.create("/work/rmw.bin", 0o644)
        base_buf = bytearray(os.urandom(PAGE_SIZE * 2))
        fs.write("/work/rmw.bin", bytes(base_buf), 0, fh)
        patch = os.urandom(1500)
        base_buf[3500:5000] = patch
        t0 = time.perf_counter()
        fs.write("/work/rmw.bin", patch, 3500, fh)
        record("write/rmw-cross-page", (time.perf_counter() - t0) * 1000)
        checks["write/rmw-cross-page-correct"] = (
            fs.read("/work/rmw.bin", PAGE_SIZE * 2, 0, fh) == bytes(base_buf)
        )

        # 5. Truncate inside page + extend zeroes tail (EC-Z06)
        fs.truncate("/work/rmw.bin", 4200)
        fs.truncate("/work/rmw.bin", 6000)
        after_trunc = fs.read("/work/rmw.bin", 6000, 0, fh)
        checks["truncate/zeroes-cut-page-tail"] = (
            after_trunc[:4200] == bytes(base_buf[:4200]) and after_trunc[4200:] == b"\x00" * 1800
        )

        # 6. Write-temp-then-rename-over-target (Git / Cargo pattern, Section 6.3)
        for i in range(n_fast):
            tmp_p = f"/work/.tmp_{i}"
            dst_p = "/work/target_config.toml"
            t0 = time.perf_counter()
            fh = fs.create(tmp_p, 0o644)
            fs.write(tmp_p, f"version = {i}\n".encode(), 0, fh)
            fs.rename(tmp_p, dst_p)
            record("workload/temp-write-rename", (time.perf_counter() - t0) * 1000)
        checks["rename/atomic-overwrite-works"] = (
            fs.read("/work/target_config.toml", 64, 0, 0) == f"version = {n_fast - 1}\n".encode()
        )

        # 7. Group commit (L2 remote push) latency (target 300-900 ms on GitHub)
        t0 = time.perf_counter()
        fs.flush_group(force=True)
        record("commit/group-flush-L2", (time.perf_counter() - t0) * 1000)

        # 8. Strict mode fsync latency (1 L2 push per fsync)
        fs.mode = "strict"
        for i in range(n_push):
            fh = fs.open("/work/read4k.bin", os.O_RDWR)
            fs.write("/work/read4k.bin", os.urandom(128), (i * 128) % 2048, fh)
            t0 = time.perf_counter()
            fs.fsync("/work/read4k.bin", 1, fh)
            record("fsync/strict-L2", (time.perf_counter() - t0) * 1000)
    finally:
        fs.close()

    summary = {k: summarize(v) for k, v in cases.items()}
    return {"location": location, "summary": summary, "checks": checks}


def print_report(res: dict) -> None:
    log(f"\n=== OctoBlock Phase A Benchmark ({res['location']}) ===")
    log(f"{'Operation':<30} {'n':>4} {'p50 ms':>10} {'p95 ms':>10} {'mean ms':>10}")
    for name, st in res["summary"].items():
        if st:
            log(f"{name:<30} {st['n']:>4} {st['p50']:>10.2f} {st['p95']:>10.2f} {st['mean']:>10.2f}")
    for chk, ok in res["checks"].items():
        log(f"check {chk:<38} {'PASS' if ok else 'FAIL'}")


def rmtree(path):
    def on_error(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=on_error)
    else:
        shutil.rmtree(path, onerror=on_error)


def cmd_selftest(_args) -> int:
    """Run against :memory: and tools/local_git_remote.py (like octospike.py selftest)."""
    r_mem = run_phase_a_benchmarks(":memory:", scale=0.5)
    print_report(r_mem)
    if not all(r_mem["checks"].values()):
        log("SELFTEST FAILED on :memory:")
        return 1

    tools_dir = Path(__file__).resolve().parent.parent / "tools"
    if (tools_dir / "local_git_remote.py").exists():
        sys.path.insert(0, str(tools_dir))
        import local_git_remote

        workdir = tempfile.mkdtemp(prefix="octoblock-spike-")
        try:
            local_git_remote.init_repo(Path(workdir) / "srv" / "vol.git")
            server = local_git_remote.serve(Path(workdir) / "srv", token="selftest-token")
            url = f"http://127.0.0.1:{server.server_port}/vol.git"
            r_git = run_phase_a_benchmarks(url, token="selftest-token", scale=0.25)
            server.shutdown()
            print_report(r_git)
            if not all(r_git["checks"].values()):
                log("SELFTEST FAILED on local_git_remote")
                return 1
        finally:
            rmtree(workdir)

    log("\nPHASE A SELFTEST PASSED")
    return 0


def cmd_bench(args) -> int:
    token = args.token or os.environ.get("OCTOPAGE_GITHUB_TOKEN") or os.environ.get("OCTOSPIKE_TOKEN")
    res = run_phase_a_benchmarks(args.repo, token=token, scale=args.scale)
    print_report(res)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(res, indent=2))
        log(f"wrote {out_path}")
    return 0 if all(res["checks"].values()) else 1


def cmd_mount(args) -> int:
    if FUSE is None:
        sys.exit("fusepy/refuse is not installed. Run: pip install fusepy (and ensure WinFsp is installed).")
    token = args.token or os.environ.get("OCTOPAGE_GITHUB_TOKEN")
    fs = OctoBlockSpikeFS(args.repo, token=token, branch=args.branch, mode=args.mode)
    log(f"Mounting {args.repo} (branch={args.branch}, mode={args.mode}) at {args.mountpoint} ...")
    try:
        FUSE(fs, args.mountpoint, foreground=True, nothreads=True)
    finally:
        fs.close()
    return 0


def main():
    parser = argparse.ArgumentParser(description="OctoBlock Phase A FUSE Spike & Benchmark Harness")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_self = sub.add_parser("selftest", help="verify FS semantics and measure against :memory: and local git remote")
    p_self.set_defaults(fn=cmd_selftest)

    p_bench = sub.add_parser("bench", help="run Phase A latency benchmarks against :memory: or OWNER/NAME")
    p_bench.add_argument("--repo", default=":memory:", help="OWNER/NAME, smart-HTTP URL, or :memory:")
    p_bench.add_argument("--token", help="GitHub token (defaults to OCTOPAGE_GITHUB_TOKEN / OCTOSPIKE_TOKEN)")
    p_bench.add_argument("--scale", type=float, default=1.0, help="scale sample counts")
    p_bench.add_argument("--out", help="optional path to write JSON results")
    p_bench.set_defaults(fn=cmd_bench)

    p_mount = sub.add_parser("mount", help="mount the volume via WinFsp / FUSE")
    p_mount.add_argument("repo", help="OWNER/NAME, URL, or :memory:")
    p_mount.add_argument("mountpoint", help="Drive letter (e.g. M:) on Windows or directory path")
    p_mount.add_argument("--branch", default="main")
    p_mount.add_argument("--mode", choices=["strict", "balanced", "relaxed"], default="balanced")
    p_mount.add_argument("--token", help="GitHub token")
    p_mount.set_defaults(fn=cmd_mount)

    args = parser.parse_args()
    sys.exit(args.fn(args))


if __name__ == "__main__":
    main()