"""
BBS+ anonymous credentials (Phase 2).

  Issuer signs attribute vector (m_1..m_L):   B = P1 + s*h0 + sum m_i*h_i
                                              A = (1/(x+e)) * B ,  signature = (A, e, s)
  Verify:                                     e(A, w + e*g2) == e(B, g2)      (w = x*g2)

Presentation = a *re-randomised* proof of knowledge of a valid signature:
  A' = r1*A,  Abar = r1*B - e*A' (= x*A'),  d = r1*B - r2*h0
  Verifier checks  e(A', w) == e(Abar, g2)   (so A' really is a randomised issuer signature)
  and two Schnorr-style equations proven jointly in zero knowledge:
     (1)  Abar - d             = e*(-A') + r2*h0
     (2)  P1 + sum_{revealed} m_i*h_i = r3*d - s'*h0 - sum_{hidden} m_j*h_j
  with r3 = 1/r1 and s' = s - r2*r3.
"""
import hashlib
from dataclasses import dataclass
from typing import Dict, List, Sequence, Set

from .group import random_scalar
from .pairing import (BACKEND, G2_GEN, ORDER, G1Point, G2Point, hash_to_g1,
                      pairing_product_is_one)
from .sigma import JointProof, prove_joint, verify_joint
from .transcript import Transcript


def encode_attribute(value) -> int:
    """Map an attribute (int or str) to a scalar mod the BLS12-381 group order."""
    if isinstance(value, int):
        return value % ORDER
    digest = hashlib.sha256(b"veilcred/bbs-attr/" + str(value).encode()).digest()
    return int.from_bytes(digest, "big") % ORDER


class BBSParams:
    """Public parameters: independent G1 generators P1, h0, h_1..h_L and the G2 generator."""
    def __init__(self, n_attributes: int):
        self.n = n_attributes
        self.P1 = hash_to_g1(b"veilcred/bbs/P1")
        self.h0 = hash_to_g1(b"veilcred/bbs/h0")
        self.h = [hash_to_g1(b"veilcred/bbs/h/%d" % i) for i in range(n_attributes)]
        self.g2 = G2_GEN


def keygen(params: BBSParams):
    sk = random_scalar(ORDER)
    return sk, sk * params.g2          # (secret x, public w = x*g2)


@dataclass
class Signature:
    A: G1Point
    e: int
    s: int


def _commit(params: BBSParams, msgs: Sequence[int], s: int) -> G1Point:
    B = params.P1 + s * params.h0
    for m, h in zip(msgs, params.h):
        B = B + m * h
    return B


def sign(params: BBSParams, sk: int, msgs: Sequence[int]) -> Signature:
    assert len(msgs) == params.n
    while True:
        e = random_scalar(ORDER)
        if (sk + e) % ORDER != 0:
            break
    s = random_scalar(ORDER)
    B = _commit(params, msgs, s)
    return Signature(pow(sk + e, -1, ORDER) * B, e, s)


def verify(params: BBSParams, pk: G2Point, msgs: Sequence[int], sig: Signature) -> bool:
    if len(msgs) != params.n or sig.A.is_infinity:
        return False
    B = _commit(params, msgs, sig.s)
    return pairing_product_is_one([(sig.A, pk + sig.e * params.g2), (-B, params.g2)])


# ----------------------------- presentations -----------------------------
@dataclass
class Presentation:
    A_prime: G1Point
    A_bar: G1Point
    d: G1Point
    revealed: Dict[int, int]
    proof: JointProof


def _statements(params, A_prime, A_bar, d, revealed):
    hidden = [j for j in range(params.n) if j not in revealed]
    st1 = ([-A_prime, params.h0], ["e", "r2"], A_bar - d)
    target2 = params.P1
    for i, m in revealed.items():
        target2 = target2 + m * params.h[i]
    bases2 = [d, -params.h0] + [-params.h[j] for j in hidden]
    keys2 = ["r3", "s_prime"] + [f"m{j}" for j in hidden]
    return [st1, (bases2, keys2, target2)]


def _transcript(pk, A_prime, A_bar, d, revealed, context):
    tr = Transcript(b"bbs-presentation", order=ORDER)
    tr.append_bytes(b"context", context)          # verifier nonce -> replay protection
    tr.append_bytes(b"pk", pk.encode())
    for name, pt in ((b"A'", A_prime), (b"Abar", A_bar), (b"d", d)):
        tr.append_point(name, pt)
    for i in sorted(revealed):
        tr.append_bytes(b"idx", i.to_bytes(4, "big"))
        tr.append_scalar(b"val", revealed[i])
    return tr


def present(params: BBSParams, pk: G2Point, sig: Signature, msgs: Sequence[int],
            reveal: Set[int], context: bytes) -> Presentation:
    B = _commit(params, msgs, sig.s)
    r1, r2 = random_scalar(ORDER), random_scalar(ORDER)
    r3 = pow(r1, -1, ORDER)
    A_prime = r1 * sig.A
    A_bar = r1 * B - sig.e * A_prime
    d = r1 * B - r2 * params.h0
    s_prime = (sig.s - r2 * r3) % ORDER

    revealed = {i: msgs[i] % ORDER for i in sorted(reveal)}
    hidden = [j for j in range(params.n) if j not in revealed]
    secrets_ = {"e": sig.e, "r2": r2, "r3": r3, "s_prime": s_prime}
    secrets_.update({f"m{j}": msgs[j] % ORDER for j in hidden})

    tr = _transcript(pk, A_prime, A_bar, d, revealed, context)
    proof = prove_joint(_statements(params, A_prime, A_bar, d, revealed), secrets_, tr)
    return Presentation(A_prime, A_bar, d, revealed, proof)


def verify_presentation(params: BBSParams, pk: G2Point, pres: Presentation,
                        context: bytes) -> bool:
    if any(not (0 <= i < params.n) for i in pres.revealed):
        return False
    if any(not (0 <= v < ORDER) for v in pres.revealed.values()):
        return False
    if pres.A_prime.is_infinity:
        return False
    if not all(p.on_curve() for p in (pres.A_prime, pres.A_bar, pres.d)):
        return False
    # A' is a genuine randomisation of an issuer signature:  e(A', w) == e(Abar, g2)
    if not pairing_product_is_one([(pres.A_prime, pk), (-pres.A_bar, params.g2)]):
        return False
    tr = _transcript(pk, pres.A_prime, pres.A_bar, pres.d, pres.revealed, context)
    return verify_joint(_statements(params, pres.A_prime, pres.A_bar, pres.d, pres.revealed),
                        pres.proof, tr)