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

Phase 3 adds predicates ("dob <= cutoff", "cgpa >= 80") on HIDDEN attributes:
  the holder commits C_j = m_j*Ga + rho_j*Gb, proves (inside the same joint proof, sharing the
  secret m_j) that C_j hides the SAME m_j the issuer signed, then range-proves m_j - t >= 0
  (or t - m_j >= 0) with range_proof.py.
"""
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .group import random_scalar
from .pairing import (BACKEND, G2_GEN, ORDER, G1Point, G2Point, hash_to_g1,
                      pairing_product_is_one)
from .range_proof import RangeProof, prove_nonneg, verify_nonneg
from .sigma import JointProof, prove_joint, verify_joint
from .transcript import Transcript


RANGE_BITS = 32                      # predicate differences must lie in [0, 2^32)
Predicate = Tuple[int, str, int]     # (attribute index, "ge" | "le", threshold)


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
        self.Ga = hash_to_g1(b"veilcred/pred/Ga")   # bases for predicate commitments
        self.Gb = hash_to_g1(b"veilcred/pred/Gb")
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
class PredicateProof:
    index: int
    op: str            # "ge": attribute >= threshold   |   "le": attribute <= threshold
    threshold: int
    proof: RangeProof


@dataclass
class Presentation:
    A_prime: G1Point
    A_bar: G1Point
    d: G1Point
    revealed: Dict[int, int]
    proof: JointProof
    commitments: Dict[int, G1Point] = field(default_factory=dict)
    predicate_proofs: List[PredicateProof] = field(default_factory=list)


def _statements(params, A_prime, A_bar, d, revealed, commitments):
    hidden = [j for j in range(params.n) if j not in revealed]
    st1 = ([-A_prime, params.h0], ["e", "r2"], A_bar - d)
    target2 = params.P1
    for i, m in revealed.items():
        target2 = target2 + m * params.h[i]
    bases2 = [d, -params.h0] + [-params.h[j] for j in hidden]
    keys2 = ["r3", "s_prime"] + [f"m{j}" for j in hidden]
    stmts = [st1, (bases2, keys2, target2)]
    # predicate commitments: C_j = m_j*Ga + rho_j*Gb, sharing the secret "m{j}" with statement 2
    for j in sorted(commitments):
        stmts.append(([params.Ga, params.Gb], [f"m{j}", f"rho{j}"], commitments[j]))
    return stmts


def _transcript(pk, A_prime, A_bar, d, revealed, context, commitments, pred_list):
    tr = Transcript(b"bbs-presentation", order=ORDER)
    tr.append_bytes(b"context", context)          # verifier nonce -> replay protection
    tr.append_bytes(b"pk", pk.encode())
    for name, pt in ((b"A'", A_prime), (b"Abar", A_bar), (b"d", d)):
        tr.append_point(name, pt)
    for i in sorted(revealed):
        tr.append_bytes(b"idx", i.to_bytes(4, "big"))
        tr.append_scalar(b"val", revealed[i])
    for j in sorted(commitments):
        tr.append_bytes(b"cidx", j.to_bytes(4, "big"))
        tr.append_point(b"C", commitments[j])
    for (i, op, t) in pred_list:                  # the claimed predicates are part of the statement
        tr.append_bytes(b"pred", f"{i}|{op}|{t}".encode())
    return tr


def _predicate_commitment(params, C, op: str, t: int):
    """Commitment to the non-negative difference: m - t  (ge)  or  t - m  (le)."""
    return C - t * params.Ga if op == "ge" else t * params.Ga - C


def _range_context(context: bytes, i: int, op: str, t: int) -> bytes:
    return context + f"|pred|{i}|{op}|{t}".encode()


def present(params: BBSParams, pk: G2Point, sig: Signature, msgs: Sequence[int],
            reveal: Set[int], context: bytes,
            predicates: Optional[Sequence[Predicate]] = None) -> Presentation:
    predicates = list(predicates or [])
    pred_attrs = sorted({i for i, _, _ in predicates})
    for i, op, _ in predicates:
        if op not in ("ge", "le") or not (0 <= i < params.n):
            raise ValueError(f"bad predicate on attribute {i}: {op}")
        if i in reveal:
            raise ValueError("a predicate is only meaningful on a HIDDEN attribute")

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

    rho = {i: random_scalar(ORDER) for i in pred_attrs}
    commitments = {i: msgs[i] % ORDER * params.Ga + rho[i] * params.Gb for i in pred_attrs}
    secrets_.update({f"rho{i}": rho[i] for i in pred_attrs})

    predicate_proofs = []
    for (i, op, t) in predicates:
        diff = msgs[i] - t if op == "ge" else t - msgs[i]
        if not (0 <= diff < 2 ** RANGE_BITS):
            raise ValueError(f"predicate not satisfied: attribute {i} {op} {t}")
        rho_d = rho[i] if op == "ge" else (-rho[i]) % ORDER
        Cd = _predicate_commitment(params, commitments[i], op, t)
        rp = prove_nonneg(params.Ga, params.Gb, diff, rho_d, RANGE_BITS, Cd,
                          _range_context(context, i, op, t))
        predicate_proofs.append(PredicateProof(i, op, t, rp))

    pred_list = [(p.index, p.op, p.threshold) for p in predicate_proofs]
    tr = _transcript(pk, A_prime, A_bar, d, revealed, context, commitments, pred_list)
    proof = prove_joint(_statements(params, A_prime, A_bar, d, revealed, commitments), secrets_, tr)
    return Presentation(A_prime, A_bar, d, revealed, proof, commitments, predicate_proofs)


def verify_presentation(params: BBSParams, pk: G2Point, pres: Presentation, context: bytes,
                        require: Optional[Sequence[Predicate]] = None) -> bool:
    """`require` is the VERIFIER's policy: every listed predicate must be proven.
    (Otherwise a holder could pick easier predicates than the ones the verifier wants.)"""
    if any(not (0 <= i < params.n) for i in pres.revealed):
        return False
    if any(not (0 <= v < ORDER) for v in pres.revealed.values()):
        return False
    if any(j in pres.revealed or not (0 <= j < params.n) for j in pres.commitments):
        return False
    if pres.A_prime.is_infinity:
        return False
    if not all(p.on_curve() for p in (pres.A_prime, pres.A_bar, pres.d)):
        return False
    # A' is a genuine randomisation of an issuer signature:  e(A', w) == e(Abar, g2)
    if not pairing_product_is_one([(pres.A_prime, pk), (-pres.A_bar, params.g2)]):
        return False

    pred_list = [(p.index, p.op, p.threshold) for p in pres.predicate_proofs]
    if any(p.op not in ("ge", "le") or p.index not in pres.commitments
           for p in pres.predicate_proofs):
        return False
    if require is not None and not set(require) <= set(pred_list):
        return False

    tr = _transcript(pk, pres.A_prime, pres.A_bar, pres.d, pres.revealed, context,
                     pres.commitments, pred_list)
    stmts = _statements(params, pres.A_prime, pres.A_bar, pres.d, pres.revealed, pres.commitments)
    if not verify_joint(stmts, pres.proof, tr):
        return False

    for p in pres.predicate_proofs:
        Cd = _predicate_commitment(params, pres.commitments[p.index], p.op, p.threshold)
        if not verify_nonneg(params.Ga, params.Gb, Cd, p.proof, RANGE_BITS,
                             _range_context(context, p.index, p.op, p.threshold)):
            return False
    return True