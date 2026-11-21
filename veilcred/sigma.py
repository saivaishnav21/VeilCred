"""
Generalised Schnorr proof: knowledge of a representation.

Statement: "I know x_1..x_k such that  target = x_1*B_1 + ... + x_k*B_k".
Everything in VeilCred (credential proofs, range proofs, ...) is built from this.
"""
from dataclasses import dataclass
from typing import Dict, Sequence, Tuple, List
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
# ---------------------------------------------------------------------------
# Joint proofs: several equations, secrets shared by name, ONE challenge.
# Used by BBS+ presentations (Phase 2) and later by range proofs / revocation.
# ---------------------------------------------------------------------------
@dataclass
class JointProof:
    Ts: List[Point]            # one commitment per equation
    responses: Dict[str, int]  # one response per named secret


def _msm(bases, scalars):
    acc = None
    for B, k in zip(bases, scalars):
        term = k * B
        acc = term if acc is None else acc + term
    return acc


def _bind_joint(tr: Transcript, statements, Ts):
    for (bases, keys, target), T in zip(statements, Ts):
        tr.append_points(b"bases", bases)
        tr.append_bytes(b"keys", "|".join(keys).encode())
        tr.append_point(b"target", target)
        tr.append_point(b"T", T)


def prove_joint(statements: Sequence[Tuple[list, List[str], Point]],
                secrets_: Dict[str, int], tr: Transcript) -> JointProof:
    """statements: [(bases, secret_names, target), ...], meaning
    target = sum_i secrets_[secret_names[i]] * bases[i]  for every statement."""
    order = statements[0][0][0].order
    ks = {name: random_scalar(order) for name in secrets_}
    Ts = [_msm(bases, [ks[k] for k in keys]) for bases, keys, _ in statements]
    _bind_joint(tr, statements, Ts)
    c = tr.challenge(b"c")
    return JointProof(Ts, {n: (ks[n] + c * x) % order for n, x in secrets_.items()})


def verify_joint(statements, proof: JointProof, tr: Transcript) -> bool:
    order = statements[0][0][0].order
    if len(proof.Ts) != len(statements):
        return False
    used = {k for _, keys, _ in statements for k in keys}
    if set(proof.responses) != used:
        return False
    if any(not (0 <= v < order) for v in proof.responses.values()):
        return False
    if any(not T.on_curve() for T in proof.Ts) or any(not t.on_curve() for _, _, t in statements):
        return False
    _bind_joint(tr, statements, proof.Ts)
    c = tr.challenge(b"c")
    for (bases, keys, target), T in zip(statements, proof.Ts):
        if _msm(bases, [proof.responses[k] for k in keys]) != T + c * target:
            return False
    return True
