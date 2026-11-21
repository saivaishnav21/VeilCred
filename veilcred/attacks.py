"""
Attack lab (Phase 5): run concrete attacks against VeilCred and record what happens.

Each attack returns (passed, note). `passed` means the SYSTEM BEHAVED CORRECTLY:
the attack was defeated (or, for the control, the honest user was accepted).

This is empirical evidence, not a security proof: it shows these specific attacks fail.
The underlying guarantees rest on assumptions (BBS+ unforgeability under q-SDH, discrete log,
random-oracle Fiat-Shamir) and on the verifier following the protocol (fresh nonces etc.).
"""
import copy
import secrets
import time
from dataclasses import dataclass
from typing import Callable, List, Tuple

from .bbs import (BBSParams, Presentation, Signature, encode_attribute, keygen, present,
                  sign, verify_presentation)
from .group import random_scalar
from .pairing import BACKEND, ORDER
from .range_proof import prove_nonneg, verify_nonneg
from .revocation import RevocationRegistry, new_handle

REV = 4                                   # attribute index holding the revocation handle
AGE18 = (1, "le", 20081121)               # dob <= 2008-11-21  <=>  age >= 18 (as of Nov 2026)


@dataclass
class Credential:
    msgs: List[int]
    sig: Signature
    handle: int


class Lab:
    """A fresh world: one university (issuer), a public blacklist, Alice (adult), Bob (minor)."""

    def __init__(self):
        self.params = BBSParams(5)
        self.sk, self.pk = keygen(self.params)
        self.registry = RevocationRegistry()
        self.alice = self.issue("Alice", 20030417)
        self.bob = self.issue("Bob", 20100101)

    def issue(self, name, dob, sk=None) -> Credential:
        handle = new_handle()
        msgs = [encode_attribute(name), dob, encode_attribute("BTech CSE"), 91, handle]
        return Credential(msgs, sign(self.params, sk or self.sk, msgs), handle)

    def prove(self, cred, nonce, predicates=(AGE18,), blacklist=None, reveal=(2,), msgs=None,
              sig=None, pk=None) -> Presentation:
        bl = self.registry.snapshot() if blacklist is None else blacklist
        return present(self.params, pk or self.pk, sig or cred.sig, msgs or cred.msgs,
                       set(reveal), nonce, predicates=list(predicates), revocation=(REV, bl))


class Verifier:
    """An honest verifier: issues fresh single-use nonces, demands age>=18 and non-revocation."""

    def __init__(self, lab: Lab, require=(AGE18,)):
        self.lab, self.require, self.issued = lab, list(require), set()

    def new_nonce(self) -> bytes:
        n = secrets.token_bytes(16)
        self.issued.add(n)
        return n

    def accept(self, pres: Presentation, nonce: bytes) -> bool:
        if nonce not in self.issued:
            return False
        self.issued.discard(nonce)                      # single use
        return verify_presentation(self.lab.params, self.lab.pk, pres, nonce,
                                   require=self.require,
                                   revocation=(REV, self.lab.registry.snapshot()))


ATTACKS: List[Tuple[str, str, Callable]] = []


def attack(category: str, name: str):
    def deco(fn):
        ATTACKS.append((category, name, fn))
        return fn
    return deco


# ------------------------------------------------------------------ control
@attack("control", "Honest adult, not revoked")
def _control(lab):
    v = Verifier(lab); n = v.new_nonce()
    ok = v.accept(lab.prove(lab.alice, n), n)
    return ok, "accepted, as it must be (otherwise the lab would prove nothing)"


# ------------------------------------------------------------------ replay
@attack("replay", "Replay a captured proof at a different verifier")
def _replay_other(lab):
    va, vb = Verifier(lab), Verifier(lab)
    na = va.new_nonce(); pres = lab.prove(lab.alice, na); va.accept(pres, na)
    nb = vb.new_nonce()
    return not vb.accept(pres, nb), "proof is bound to the first verifier's nonce"


@attack("replay", "Replay the same proof at the same verifier")
def _replay_same(lab):
    v = Verifier(lab); n = v.new_nonce(); pres = lab.prove(lab.alice, n)
    first = v.accept(pres, n)
    second = v.accept(pres, n)
    return first and not second, "needs verifier-side single-use nonces (an application duty)"


# ------------------------------------------------------------------ forgery
@attack("forgery", "Self-issued credential from a rogue issuer")
def _rogue_issuer(lab):
    rogue_sk, _ = keygen(lab.params)
    cred = lab.issue("Mallory", 19900101, sk=rogue_sk)
    v = Verifier(lab); n = v.new_nonce()
    return not v.accept(lab.prove(cred, n), n), "pairing check e(A',w)=e(Abar,g2) fails under the real issuer key"


@attack("forgery", "Tamper with a disclosed attribute")
def _tamper_revealed(lab):
    v = Verifier(lab); n = v.new_nonce(); pres = lab.prove(lab.alice, n)
    forged = copy.deepcopy(pres); forged.revealed[2] = encode_attribute("PhD Physics")
    return not v.accept(forged, n), "disclosed value is part of the proven statement"


@attack("forgery", "Claim an attribute the issuer never signed (CGPA 10.0)")
def _lie(lab):
    lie = list(lab.alice.msgs); lie[3] = 100
    v = Verifier(lab); n = v.new_nonce()
    pres = lab.prove(lab.alice, n, reveal=(3,), msgs=lie)
    return not v.accept(pres, n), "no valid signature exists for the altered attribute vector"


@attack("forgery", "Splice an adult's birth date into a minor's credential")
def _splice(lab):
    msgs = list(lab.bob.msgs); msgs[1] = lab.alice.msgs[1]
    v = Verifier(lab); n = v.new_nonce()
    pres = lab.prove(lab.bob, n, msgs=msgs)             # predicate is satisfiable, signature isn't
    return not v.accept(pres, n), "mix-and-match across credentials breaks the signature"


@attack("forgery", "Degenerate points (A' = A-bar = infinity)")
def _degenerate(lab):
    v = Verifier(lab); n = v.new_nonce(); pres = lab.prove(lab.alice, n)
    pres.A_prime = pres.A_prime * 0
    pres.A_bar = pres.A_bar * 0
    return not v.accept(pres, n), "verifier rejects A' = identity (it would pass the pairing check trivially)"


@attack("forgery", "Malleate the proof (change one response scalar)")
def _maul(lab):
    v = Verifier(lab); n = v.new_nonce(); pres = lab.prove(lab.alice, n)
    pres.proof.responses["e"] = (pres.proof.responses["e"] + 1) % ORDER
    return not v.accept(pres, n), "Fiat-Shamir equations no longer hold"


# ------------------------------------------------------------------ predicates
@attack("predicate", "Minor tries to prove age >= 18 honestly")
def _minor_honest(lab):
    v = Verifier(lab); n = v.new_nonce()
    try:
        lab.prove(lab.bob, n)
    except ValueError:
        return True, "prover cannot even build the proof (difference is negative)"
    return False, "a minor produced an age proof"


@attack("predicate", "Minor wraps a negative difference around 2^32")
def _wraparound(lab):
    p = lab.params
    rho = random_scalar(ORDER)
    Cd = (-5) * p.Ga + rho * p.Gb                       # commitment to a NEGATIVE value
    rp = prove_nonneg(p.Ga, p.Gb, 2 ** 32 - 5, rho, 32, Cd, b"ctx")   # cheat: use the wrapped value
    return not verify_nonneg(p.Ga, p.Gb, Cd, rp, 32, b"ctx"), "bits sum to 2^32-5, not -5, so the sum check fails"


@attack("predicate", "Swap the birth-date commitment for one to a different value")
def _swap(lab):
    v = Verifier(lab); n = v.new_nonce(); pres = lab.prove(lab.alice, n)
    pres.commitments[1] = 19990101 * lab.params.Ga + random_scalar(ORDER) * lab.params.Gb
    return not v.accept(pres, n), "commitment no longer matches the value the issuer signed"


@attack("predicate", "Minor proves a weaker predicate than the verifier asked for")
def _downgrade(lab):
    v = Verifier(lab); n = v.new_nonce()
    pres = lab.prove(lab.bob, n, predicates=[(1, "le", 20300101)])    # genuinely true for Bob
    return not v.accept(pres, n), "verifier policy `require` is not satisfied"


# ------------------------------------------------------------------ revocation
@attack("revocation", "Revoked holder tries to present")
def _revoked(lab):
    lab.registry.revoke(lab.bob.handle)
    v = Verifier(lab); n = v.new_nonce()
    try:
        lab.prove(lab.bob, n, predicates=[])
    except ValueError:
        return True, "no inverse of (handle - handle) exists, so no proof can be built"
    return False, "a revoked credential produced a proof"


@attack("revocation", "Present against a stale (pre-revocation) blacklist")
def _stale(lab):
    lab.registry.revoke(new_handle())
    old = lab.registry.snapshot()
    v = Verifier(lab); n = v.new_nonce()
    pres = lab.prove(lab.alice, n, predicates=[AGE18], blacklist=old)
    lab.registry.revoke(lab.alice.handle)               # revoked after the holder grabbed the old list
    return not v.accept(pres, n), "proof is bound to the exact list; the verifier's list is newer"


@attack("revocation", "Strip own handle out of the blacklist before proving")
def _strip(lab):
    real_other = new_handle()
    lab.registry.revoke(real_other); lab.registry.revoke(lab.alice.handle)
    fake = [real_other, new_handle()]                   # own handle replaced by a harmless one
    v = Verifier(lab); n = v.new_nonce()
    pres = lab.prove(lab.alice, n, blacklist=fake)
    return not v.accept(pres, n), "statements are rebuilt from the verifier's own list"


# ------------------------------------------------------------------ privacy
def _fingerprint(pres: Presentation) -> set:
    """Every group element / scalar in a presentation that a verifier could compare
    (excluding deliberately disclosed attributes)."""
    items = {p.encode() for p in (pres.A_prime, pres.A_bar, pres.d, *pres.commitments.values(), *pres.proof.Ts)}
    items |= {int(s).to_bytes(32, "big") for s in pres.proof.responses.values()}
    for pp in pres.predicate_proofs:
        items |= {c.encode() for c in pp.proof.Cs}
        for bp in pp.proof.bit_proofs:
            items |= {bp.T0.encode(), bp.T1.encode()}
            items |= {int(x).to_bytes(32, "big") for x in (bp.c0, bp.c1, bp.s0, bp.s1)}
    return items


@attack("privacy", "Colluding verifiers try to link presentations of the same holder")
def _linkability(lab):
    carol = lab.issue("Carol", 20010202)
    holders = [lab.alice, carol]
    runs = []                                           # (holder index, VeilCred fingerprint, naive fingerprint)
    for h, cred in enumerate(holders):
        for _ in range(3):
            pres = lab.prove(cred, secrets.token_bytes(16))
            naive = {cred.sig.A.encode(), int(cred.sig.e).to_bytes(32, "big"), int(cred.sig.s).to_bytes(32, "big")}
            runs.append((h, _fingerprint(pres), naive))
    same_pairs = vc_linked = naive_linked = cross_naive = 0
    for i in range(len(runs)):
        for j in range(i + 1, len(runs)):
            same = runs[i][0] == runs[j][0]
            same_pairs += same
            vc_hit = bool(runs[i][1] & runs[j][1])
            naive_hit = bool(runs[i][2] & runs[j][2])
            vc_linked += vc_hit
            naive_linked += naive_hit and same
            cross_naive += naive_hit and not same
    ok = vc_linked == 0 and naive_linked == same_pairs and cross_naive == 0
    return ok, (f"VeilCred: {vc_linked} linkable pairs; naive 'show the signature' baseline: "
                f"{naive_linked}/{same_pairs} same-holder pairs linked. "
                "(Disclosed attributes can still link if they are identifying.)")


# ------------------------------------------------------------------ runner
@dataclass
class Result:
    category: str
    name: str
    passed: bool
    note: str
    seconds: float


def run_all() -> List[Result]:
    results = []
    for category, name, fn in ATTACKS:
        lab = Lab()                                     # fresh world per attack
        t = time.time()
        try:
            passed, note = fn(lab)
        except Exception as e:                          # an unexpected crash is a failure, not a defence
            passed, note = False, f"unexpected exception: {type(e).__name__}: {e}"
        results.append(Result(category, name, bool(passed), note, time.time() - t))
    return results