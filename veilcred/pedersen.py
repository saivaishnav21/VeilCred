"""Pedersen vector commitments + selective-disclosure proofs over them."""
import hashlib
from dataclasses import dataclass
from typing import Dict, List, Sequence, Set
from .group import N, Point, hash_to_point, random_scalar, sum_points
from .sigma import RepProof, prove_representation, verify_representation
from .transcript import Transcript


def encode_attribute(value) -> int:
    """Map an attribute (int or str) to a scalar. Strings are hashed."""
    if isinstance(value, int):
        return value % N
    digest = hashlib.sha256(b"veilcred/attr/" + str(value).encode()).digest()
    return int.from_bytes(digest, "big") % N


class PedersenParams:
    """Independent generators h, g_1..g_n with unknown mutual discrete logs."""
    def __init__(self, n_attributes: int):
        self.n = n_attributes
        self.h = hash_to_point(b"veilcred/pedersen/h")
        self.g = [hash_to_point(b"veilcred/pedersen/g/%d" % i) for i in range(n_attributes)]

    def commit(self, attrs: Sequence[int], r: int = None):
        assert len(attrs) == self.n
        r = random_scalar() if r is None else r
        C = r * self.h + sum_points(m * g for m, g in zip(attrs, self.g))
        return C, r

    def open_check(self, C: Point, attrs: Sequence[int], r: int) -> bool:
        return C == self.commit(attrs, r)[0]


@dataclass
class Disclosure:
    revealed: Dict[int, int]  # attribute index -> value
    proof: RepProof


def _setup(params: PedersenParams, C: Point, revealed: Dict[int, int], context: bytes):
    # target = C - sum(revealed m_i * g_i)  =  r*h + sum(hidden m_j * g_j)
    target = C - sum_points(m * params.g[i] for i, m in revealed.items())
    hidden = [j for j in range(params.n) if j not in revealed]
    bases = [params.h] + [params.g[j] for j in hidden]
    tr = Transcript(b"selective-disclosure")
    tr.append_bytes(b"context", context)  # verifier nonce -> replay protection
    tr.append_point(b"C", C)
    for i in sorted(revealed):
        tr.append_bytes(b"idx", i.to_bytes(4, "big"))
        tr.append_scalar(b"val", revealed[i])
    return target, hidden, bases, tr


def prove_disclosure(params: PedersenParams, attrs: List[int], r: int, C: Point,
                     reveal: Set[int], context: bytes) -> Disclosure:
    revealed = {i: attrs[i] % N for i in sorted(reveal)}
    target, hidden, bases, tr = _setup(params, C, revealed, context)
    secrets_ = [r] + [attrs[j] for j in hidden]
    return Disclosure(revealed, prove_representation(bases, secrets_, target, tr))


def verify_disclosure(params: PedersenParams, C: Point, d: Disclosure, context: bytes) -> bool:
    if any(not (0 <= i < params.n) for i in d.revealed):
        return False
    target, _, bases, tr = _setup(params, C, d.revealed, context)
    return verify_representation(bases, target, d.proof, tr)
