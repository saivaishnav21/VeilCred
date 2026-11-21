"""
Generalised Schnorr proof: knowledge of a representation.

Statement: "I know x_1..x_k such that  target = x_1*B_1 + ... + x_k*B_k".
Everything in VeilCred (credential proofs, range proofs, ...) is built from this.
"""
from dataclasses import dataclass
from typing import List
from .group import N, Point, random_scalar, sum_points
from .transcript import Transcript


@dataclass
class RepProof:
    T: Point              # commitment (first message)
    responses: List[int]  # s_i = k_i + c * x_i


def _bind_statement(tr: Transcript, bases, target, T):
    tr.append_points(b"bases", bases)
    tr.append_point(b"target", target)
    tr.append_point(b"T", T)


def prove_representation(bases: List[Point], secrets_: List[int], target: Point,
                         tr: Transcript) -> RepProof:
    assert len(bases) == len(secrets_)
    ks = [random_scalar() for _ in bases]
    T = sum_points(k * B for k, B in zip(ks, bases))
    _bind_statement(tr, bases, target, T)
    c = tr.challenge(b"c")
    return RepProof(T, [(k + c * x) % N for k, x in zip(ks, secrets_)])


def verify_representation(bases: List[Point], target: Point, proof: RepProof,
                          tr: Transcript) -> bool:
    if len(proof.responses) != len(bases):
        return False
    if not (target.on_curve() and proof.T.on_curve()):
        return False
    if any(not (0 <= s < N) for s in proof.responses):
        return False
    _bind_statement(tr, bases, target, proof.T)
    c = tr.challenge(b"c")
    lhs = sum_points(s * B for s, B in zip(proof.responses, bases))
    return lhs == proof.T + c * target
