"""
Zero-knowledge range proofs (Phase 3), built only from Pedersen commitments + OR-proofs.

Goal: given a commitment  Cd = d*Ga + rho*Gb,  prove  0 <= d < 2^bits  without revealing d.

  1. Write d in binary:  d = sum 2^i * b_i.
  2. Commit to every bit:  C_i = b_i*Ga + r_i*Gb,  choosing the r_i so that
         sum 2^i * C_i == Cd      (the verifier checks this directly).
  3. For every bit prove  "b_i = 0  OR  b_i = 1"  with a Cramer-Damgard-Schoenmakers
     OR-proof:   (C_i = r_i*Gb)   OR   (C_i - Ga = r_i*Gb).
     The branch the prover does NOT know is *simulated*; the verifier cannot tell which.

Generic over any prime-order group exposing the Point interface (secp256k1 or BLS12-381 G1).
"""
from dataclasses import dataclass
from typing import List

from .group import random_scalar
from .transcript import Transcript


@dataclass
class BitProof:
    T0: object
    T1: object
    c0: int
    c1: int
    s0: int
    s1: int


@dataclass
class RangeProof:
    Cs: List[object]          # one commitment per bit
    bit_proofs: List[BitProof]


def _transcript(Ga, Gb, Cd, Cs, context: bytes) -> Transcript:
    tr = Transcript(b"veilcred/range", order=Ga.order)
    tr.append_bytes(b"context", context)
    tr.append_points(b"gens", [Ga, Gb])
    tr.append_point(b"Cd", Cd)
    tr.append_points(b"Cs", Cs)
    return tr


def _prove_bit(Ga, Gb, Ci, bit: int, r: int, tr: Transcript) -> BitProof:
    order = Ga.order
    Y = [Ci, Ci - Ga]                     # statement j: Y_j = r * Gb
    real, fake = bit, 1 - bit
    k = random_scalar(order)
    c_fake, s_fake = random_scalar(order), random_scalar(order)
    T = [None, None]
    T[real] = k * Gb                                   # honest commitment
    T[fake] = s_fake * Gb - c_fake * Y[fake]           # simulated commitment
    tr.append_points(b"T", T)
    c = tr.challenge(b"c")
    c_real = (c - c_fake) % order                      # challenges must sum to c
    s_real = (k + c_real * r) % order
    cs, ss = [0, 0], [0, 0]
    cs[real], cs[fake] = c_real, c_fake
    ss[real], ss[fake] = s_real, s_fake
    return BitProof(T[0], T[1], cs[0], cs[1], ss[0], ss[1])


def _verify_bit(Ga, Gb, Ci, bp: BitProof, tr: Transcript) -> bool:
    order = Ga.order
    scalars = (bp.c0, bp.c1, bp.s0, bp.s1)
    if any(not (0 <= v < order) for v in scalars):
        return False
    tr.append_points(b"T", [bp.T0, bp.T1])
    c = tr.challenge(b"c")
    if (bp.c0 + bp.c1) % order != c:
        return False
    if bp.s0 * Gb != bp.T0 + bp.c0 * Ci:
        return False
    if bp.s1 * Gb != bp.T1 + bp.c1 * (Ci - Ga):
        return False
    return True


def prove_nonneg(Ga, Gb, d: int, rho: int, bits: int, Cd, context: bytes) -> RangeProof:
    """Prove 0 <= d < 2^bits for Cd = d*Ga + rho*Gb."""
    order = Ga.order
    if not (0 <= d < 2 ** bits):
        raise ValueError("value outside the provable range")
    b = [(d >> i) & 1 for i in range(bits)]
    r = [random_scalar(order) for _ in range(bits - 1)]
    partial = sum(pow(2, i, order) * r[i] for i in range(bits - 1)) % order
    r.append((rho - partial) * pow(pow(2, bits - 1, order), -1, order) % order)
    Cs = [b[i] * Ga + r[i] * Gb for i in range(bits)]
    tr = _transcript(Ga, Gb, Cd, Cs, context)
    return RangeProof(Cs, [_prove_bit(Ga, Gb, Cs[i], b[i], r[i], tr) for i in range(bits)])


def verify_nonneg(Ga, Gb, Cd, proof: RangeProof, bits: int, context: bytes) -> bool:
    if len(proof.Cs) != bits or len(proof.bit_proofs) != bits:
        return False
    if not all(C.on_curve() for C in proof.Cs):
        return False
    acc = None                                   # Horner: sum 2^i * C_i
    for C in reversed(proof.Cs):
        acc = C if acc is None else acc + acc + C
    if acc != Cd:
        return False
    tr = _transcript(Ga, Gb, Cd, proof.Cs, context)
    return all(_verify_bit(Ga, Gb, C, bp, tr) for C, bp in zip(proof.Cs, proof.bit_proofs))