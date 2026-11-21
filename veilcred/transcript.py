"""Fiat-Shamir transcript: turns interactive sigma protocols into non-interactive ones."""
import hashlib
from .group import N, Point


class Transcript:
    def __init__(self, label: bytes, order: int = N):
        self.order = order
        self._h = hashlib.sha512()
        self._absorb(b"veilcred/v1")
        self._absorb(label)

    def _absorb(self, data: bytes):
        # length-prefixing prevents ambiguity between concatenated fields
        self._h.update(len(data).to_bytes(8, "big") + data)

    def append_bytes(self, label: bytes, data: bytes):
        self._absorb(label)
        self._absorb(data)

    def append_point(self, label: bytes, p: Point):
        self.append_bytes(label, p.encode())

    def append_points(self, label: bytes, pts):
        self.append_bytes(label + b"/len", len(pts).to_bytes(4, "big"))
        for p in pts:
            self.append_point(label, p)

    def append_scalar(self, label: bytes, s: int):
        self.append_bytes(label, (s % self.order).to_bytes(32, "big"))

    def challenge(self, label: bytes) -> int:
        h = self._h.copy()
        h.update(label)
        digest = h.digest()
        self._absorb(digest)  # chain, so later challenges depend on earlier ones
        return int.from_bytes(digest, "big") % self.order