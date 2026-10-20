"""Read and sanitize hnswlib index files as persisted by Chroma, without loading the index.

Two ways these files hold data they shouldn't:

1. Deletion only sets a flag on the element; the vector bytes stay in data_level0.bin
   until the index is rebuilt.
2. Chroma's hnswlib fork allocates its buffers with malloc (never zeroed) and persists
   them. Slots past cur_element_count were never written by the index, so on disk they
   hold whatever that memory held before: often other collections' documents. hnswlib
   zeroes each data_level0 slot when it is first used, so those below the count are clean.
   length.bin holds each vector's norm, but only cosine indexes (normalize=true) ever write
   it or read it back. For l2 and ip every byte of length.bin is leftover memory.
"""

from __future__ import annotations

import mmap
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

from .pii import find_pii

# offsetLevel0, max_elements, cur_element_count, size_data_per_element,
# label_offset, offsetData, maxlevel, enterpoint_node, maxM, maxM0, M
_HEADER = struct.Struct("<QQQQQQiIQQQ")
_DELETE_MARK = 0x01  # hnswlib marks deletion in byte 2 of the level-0 link list header
_LENGTH_ENTRY = 4  # one float per element
# Leftover memory is usually allocator pointers; text runs this long are data.
_TEXT_RUN = re.compile(rb"[\x20-\x7e]{8,}")


@dataclass
class HnswIndex:
    path: Path
    vectors: int  # elements physically stored on disk
    deleted: int  # of which flagged deleted (bytes still present)
    element_size: int
    normalized: bool = True  # cosine: length.bin holds real norms below the count
    leaked_bytes: int = 0  # non-zero bytes in never-used capacity slots (zeroed by fix)
    leaked_text: int = 0  # printable text fragments among them — i.e. actual data
    leaked_pii: set[tuple[str, bytes]] = field(default_factory=set)

    def unused_regions(self) -> list[tuple[Path, int]]:
        """(file, offset) pairs from which everything to EOF is unused capacity."""
        return [
            (self.path / "data_level0.bin", self.vectors * self.element_size),
            (self.path / "length.bin", self.vectors * _LENGTH_ENTRY if self.normalized else 0),
        ]


def _parse(header: bytes, data_len: int) -> tuple[int, int] | None:
    # Chroma's fork prefixes a 4-byte format version; upstream hnswlib does not.
    for prefix in (4, 0):
        if len(header) < prefix + _HEADER.size:
            continue
        _, max_el, count, size, label_off, data_off, *_ = _HEADER.unpack_from(header, prefix)
        if 0 < size < 1 << 24 and label_off + 8 <= size and data_off < size and count <= max(max_el, 1) * 2 and count * size <= data_len:
            return count, size
    return None


_CHUNK = 8 << 20


def _scan_tail(path: Path, offset: int, index: HnswIndex) -> None:
    """Look at everything from offset to EOF in chunks, so huge indexes don't need huge memory."""
    overlap = 256  # long enough for any PII value straddling a chunk boundary
    with path.open("rb") as f:
        f.seek(offset)
        carry = b""
        open_run = False  # a text run touched the end of the last window and may continue
        while chunk := f.read(_CHUNK):
            nonzero = len(chunk) - chunk.count(0)
            index.leaked_bytes += nonzero
            window = carry + chunk
            if nonzero or open_run:
                open_run = False
                for m in _TEXT_RUN.finditer(window):
                    if m.end() < len(carry):
                        continue  # counted with the previous window
                    if m.end() == len(window):
                        open_run = True  # count it once we see where it ends
                    else:
                        index.leaked_text += 1
                index.leaked_pii.update(find_pii(window))
            carry = window[-overlap:]
        index.leaked_text += open_run


def read_index(segment_dir: Path, normalized: bool = True) -> HnswIndex | None:
    """normalized: whether the index is cosine. When unsure, pass True: it only protects more bytes."""
    header_path = segment_dir / "header.bin"
    data_path = segment_dir / "data_level0.bin"
    if not header_path.exists() or not data_path.exists():
        return None
    data_len = data_path.stat().st_size
    parsed = _parse(header_path.read_bytes(), data_len)
    if parsed is None:
        raise ValueError(f"unrecognized HNSW header in {header_path}")
    count, size = parsed
    deleted = 0
    if count:
        with data_path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            deleted = sum(1 for i in range(count) if mm[i * size + 2] & _DELETE_MARK)
    index = HnswIndex(segment_dir, count, deleted, size, normalized)
    for path, offset in index.unused_regions():
        if path.exists() and path.stat().st_size > offset:
            _scan_tail(path, offset, index)
    return index


def zero_unused(index: HnswIndex) -> int:
    """Overwrite never-used capacity slots with zeros, in place, keeping file sizes."""
    zeroed = 0
    for path, offset in index.unused_regions():
        if not path.exists():
            continue
        size = path.stat().st_size
        if size <= offset:
            continue
        with path.open("r+b") as f:
            f.seek(offset)
            remaining = size - offset
            while remaining:
                n = min(remaining, 1 << 20)
                f.write(b"\x00" * n)
                remaining -= n
            f.flush()
        zeroed += size - offset
    return zeroed
