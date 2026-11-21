"""
Privacy-preserving revocation (Phase 4): a public blacklist of revocation handles.

Every credential carries a random, issuer-signed *revocation handle* as one hidden attribute.
To revoke a credential the issuer publishes its handle. A holder then proves, in zero
knowledge, that their (hidden) handle differs from EVERY handle on the list, without
revealing the handle. See bbs.py for the proof itself.

Cost is linear in the size of the list; accumulators / Merkle trees can make it sub-linear
(listed as future work in the README).
"""
import secrets
from typing import List


def new_handle() -> int:
    """A fresh random 128-bit handle (small enough to never wrap around the group order)."""
    return secrets.randbits(128) | (1 << 127)


class RevocationRegistry:
    """The issuer's public revocation list. `epoch` increases with every revocation."""

    def __init__(self):
        self._revoked: List[int] = []
        self.epoch = 0

    def revoke(self, handle: int) -> None:
        if handle not in self._revoked:
            self._revoked.append(handle)
            self.epoch += 1

    def snapshot(self) -> List[int]:
        """The list a verifier hands to holders ("prove you are not on THIS list")."""
        return list(self._revoked)