import copy
import pytest

from veilcred.group import hash_to_point, random_scalar, N
from veilcred.transcript import Transcript
from veilcred.sigma import prove_joint, verify_joint
from veilcred.bbs import (BBSParams, keygen, sign, present, verify_presentation,
                          encode_attribute)
from veilcred.revocation import RevocationRegistry, new_handle

# ---------- the "x != 0" gadget on its own (secp256k1, real group math) ----------
Ga, Gb = hash_to_point(b"test/Ga"), hash_to_point(b"test/Gb")


def test_nonzero_gadget_accepts_nonzero_and_rejects_zero():
    rho = random_scalar()
    for x, should_pass in ((5, True), (0, False)):
        C = x * Ga + rho * Gb
        y = pow(x, -1, N) if x else 1            # for x = 0 no inverse exists: cheater guesses
        t = (-y * rho) % N
        stmt = [([C, Gb], ["y", "t"], Ga)]       # Ga = y*C + t*Gb  <=>  x*y = 1
        proof = prove_joint(stmt, {"y": y, "t": t}, Transcript(b"gadget"))
        assert verify_joint(stmt, proof, Transcript(b"gadget")) == should_pass


# ---------- revocation inside BBS+ presentations ----------
REV = 4                                         # attribute index holding the revocation handle


def issue(params, sk, name="Alice", dob=20030417):
    handle = new_handle()
    msgs = [encode_attribute(name), dob, encode_attribute("BTech CSE"), 91, handle]
    return msgs, sign(params, sk, msgs), handle


def world():
    params = BBSParams(5)
    sk, pk = keygen(params)
    return params, sk, pk


def test_valid_credential_passes_with_empty_and_nonempty_blacklist():
    params, sk, pk = world()
    msgs, sig, _ = issue(params, sk)
    for others in (0, 3):
        blacklist = [new_handle() for _ in range(others)]
        pres = present(params, pk, sig, msgs, {2}, b"n", revocation=(REV, blacklist))
        assert verify_presentation(params, pk, pres, b"n", revocation=(REV, blacklist))


def test_revoked_credential_cannot_produce_a_proof():
    params, sk, pk = world()
    msgs, sig, handle = issue(params, sk)
    registry = RevocationRegistry()
    registry.revoke(new_handle())
    registry.revoke(handle)
    with pytest.raises(ValueError):
        present(params, pk, sig, msgs, {2}, b"n", revocation=(REV, registry.snapshot()))


def test_stale_blacklist_is_rejected():
    # Holder proves against the OLD list (before revocation); verifier insists on the NEW list.
    params, sk, pk = world()
    msgs, sig, handle = issue(params, sk)
    registry = RevocationRegistry()
    registry.revoke(new_handle())
    old = registry.snapshot()
    pres = present(params, pk, sig, msgs, {2}, b"n", revocation=(REV, old))
    assert verify_presentation(params, pk, pres, b"n", revocation=(REV, old))
    registry.revoke(handle)                                     # credential gets revoked
    assert not verify_presentation(params, pk, pres, b"n", revocation=(REV, registry.snapshot()))


def test_presentation_without_revocation_proof_fails_when_verifier_requires_one():
    params, sk, pk = world()
    msgs, sig, _ = issue(params, sk)
    pres = present(params, pk, sig, msgs, {2}, b"n")            # holder "forgets" the revocation proof
    assert not verify_presentation(params, pk, pres, b"n", revocation=(REV, [new_handle()]))


def test_revocation_handle_must_stay_hidden():
    params, sk, pk = world()
    msgs, sig, _ = issue(params, sk)
    with pytest.raises(ValueError):
        present(params, pk, sig, msgs, {REV}, b"n", revocation=(REV, [new_handle()]))


def test_revocation_combined_with_predicates():
    params, sk, pk = world()
    msgs, sig, _ = issue(params, sk)
    age18, cgpa8 = (1, "le", 20081121), (3, "ge", 80)
    blacklist = [new_handle(), new_handle()]
    pres = present(params, pk, sig, msgs, {2}, b"n", predicates=[age18, cgpa8],
                   revocation=(REV, blacklist))
    assert set(pres.revealed) == {2}
    assert verify_presentation(params, pk, pres, b"n", require=[age18, cgpa8],
                               revocation=(REV, blacklist))


def test_replay_rejected_with_revocation():
    params, sk, pk = world()
    msgs, sig, _ = issue(params, sk)
    bl = [new_handle()]
    pres = present(params, pk, sig, msgs, {2}, b"verifier-A", revocation=(REV, bl))
    assert not verify_presentation(params, pk, pres, b"verifier-B", revocation=(REV, bl))


def test_revocation_proofs_are_unlinkable():
    params, sk, pk = world()
    msgs, sig, _ = issue(params, sk)
    bl = [new_handle(), new_handle()]
    p1 = present(params, pk, sig, msgs, {2}, b"n1", revocation=(REV, bl))
    p2 = present(params, pk, sig, msgs, {2}, b"n2", revocation=(REV, bl))
    assert p1.commitments[REV] != p2.commitments[REV]           # nothing stable to link on
    assert p1.A_prime != p2.A_prime


def test_blacklist_entry_swapped_by_holder_is_rejected():
    # Holder proves against a list where the revoked handle was replaced by a harmless one.
    params, sk, pk = world()
    msgs, sig, handle = issue(params, sk)
    real_list = [new_handle(), handle]
    fake_list = [real_list[0], new_handle()]
    pres = present(params, pk, sig, msgs, {2}, b"n", revocation=(REV, fake_list))
    assert not verify_presentation(params, pk, pres, b"n", revocation=(REV, real_list))