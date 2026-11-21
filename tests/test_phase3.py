import copy
import pytest

from veilcred.group import G, hash_to_point, random_scalar, N
from veilcred.range_proof import prove_nonneg, verify_nonneg
from veilcred.bbs import (BBSParams, keygen, sign, present, verify_presentation,
                          encode_attribute)

# ---------- range proof on its own (runs over secp256k1, i.e. real group math) ----------
Ga, Gb = hash_to_point(b"test/Ga"), hash_to_point(b"test/Gb")
BITS = 8


def commit(d, rho):
    return d * Ga + rho * Gb


def test_range_proof_accepts_values_in_range():
    for d in (0, 1, 37, 255):
        rho = random_scalar()
        Cd = commit(d, rho)
        rp = prove_nonneg(Ga, Gb, d, rho, BITS, Cd, b"ctx")
        assert verify_nonneg(Ga, Gb, Cd, rp, BITS, b"ctx")


def test_range_proof_refuses_out_of_range_value():
    with pytest.raises(ValueError):
        prove_nonneg(Ga, Gb, 256, 5, BITS, commit(256, 5), b"ctx")
    with pytest.raises(ValueError):
        prove_nonneg(Ga, Gb, -1, 5, BITS, commit(-1, 5), b"ctx")


def test_range_proof_bound_to_its_commitment_and_context():
    rho = random_scalar()
    Cd = commit(37, rho)
    rp = prove_nonneg(Ga, Gb, 37, rho, BITS, Cd, b"ctx")
    assert not verify_nonneg(Ga, Gb, commit(38, rho), rp, BITS, b"ctx")   # other value
    assert not verify_nonneg(Ga, Gb, Cd, rp, BITS, b"other-ctx")          # replay
    bad = copy.deepcopy(rp)
    bad.Cs[3] = bad.Cs[3] + Ga                                            # tamper with a bit commitment
    assert not verify_nonneg(Ga, Gb, Cd, bad, BITS, b"ctx")


def test_a_bit_that_is_not_0_or_1_cannot_be_proven():
    # A cheater commits to bit value 2 in position 0 (and compensates elsewhere so the sum still
    # matches). The OR-proof for that bit cannot be completed honestly, so verification fails.
    rho = random_scalar()
    d = 5
    Cd = commit(d, rho)
    rp = prove_nonneg(Ga, Gb, d, rho, BITS, Cd, b"ctx")
    forged = copy.deepcopy(rp)
    forged.Cs[0] = forged.Cs[0] + Ga          # now commits to 2 instead of 1
    forged.Cs[1] = forged.Cs[1] - 2 * Ga      # compensate so sum(2^i C_i) is unchanged
    assert not verify_nonneg(Ga, Gb, Cd, forged, BITS, b"ctx")


# ---------- predicates inside BBS+ presentations ----------
FIELDS = ["name", "dob", "degree", "cgpa", "id"]
DOB, CGPA = 20030417, 91                       # YYYYMMDD as an integer, CGPA x10
AGE18_CUTOFF = 20081121                        # born on/before this date => age >= 18
AGE18 = (1, "le", AGE18_CUTOFF)
CGPA80 = (3, "ge", 80)


def setup(dob=DOB):
    params = BBSParams(5)
    sk, pk = keygen(params)
    msgs = [encode_attribute("Alice"), dob, encode_attribute("BTech CSE"), CGPA,
            encode_attribute("ID-48213")]
    return params, pk, msgs, sign(params, sk, msgs)


def test_predicates_verify_and_hide_the_values():
    params, pk, msgs, sig = setup()
    pres = present(params, pk, sig, msgs, {2}, b"n", predicates=[AGE18, CGPA80])
    assert set(pres.revealed) == {2}                       # only the degree is disclosed
    assert verify_presentation(params, pk, pres, b"n", require=[AGE18, CGPA80])


def test_underage_holder_cannot_prove_age_predicate():
    params, pk, msgs, sig = setup(dob=20100101)            # born 2010 -> not yet 18
    with pytest.raises(ValueError):
        present(params, pk, sig, msgs, {2}, b"n", predicates=[AGE18])


def test_verifier_policy_must_be_met():
    params, pk, msgs, sig = setup()
    pres = present(params, pk, sig, msgs, {2}, b"n", predicates=[AGE18])
    assert verify_presentation(params, pk, pres, b"n", require=[AGE18])
    assert not verify_presentation(params, pk, pres, b"n", require=[CGPA80])          # missing predicate
    assert not verify_presentation(params, pk, pres, b"n", require=[(1, "le", 19990101)])  # harder cutoff


def test_tampered_threshold_rejected():
    params, pk, msgs, sig = setup()
    pres = present(params, pk, sig, msgs, {2}, b"n", predicates=[AGE18])
    forged = copy.deepcopy(pres)
    forged.predicate_proofs[0].threshold = 20201231        # pretend a looser cutoff was proven
    assert not verify_presentation(params, pk, forged, b"n")


def test_replay_rejected_with_predicates():
    params, pk, msgs, sig = setup()
    pres = present(params, pk, sig, msgs, {2}, b"verifier-A", predicates=[AGE18])
    assert not verify_presentation(params, pk, pres, b"verifier-B")


def test_predicate_commitment_must_match_signed_attribute():
    # Swap in a commitment to a different (qualifying) value: it no longer matches the value the
    # issuer signed, so the joint proof fails.
    params, pk, msgs, sig = setup()
    pres = present(params, pk, sig, msgs, {2}, b"n", predicates=[AGE18])
    forged = copy.deepcopy(pres)
    forged.commitments[1] = 19990101 * params.Ga + random_scalar(N) * params.Gb
    assert not verify_presentation(params, pk, forged, b"n")


def test_predicate_on_revealed_attribute_is_rejected():
    params, pk, msgs, sig = setup()
    with pytest.raises(ValueError):
        present(params, pk, sig, msgs, {1}, b"n", predicates=[AGE18])


def test_presentations_with_predicates_still_unlinkable():
    params, pk, msgs, sig = setup()
    p1 = present(params, pk, sig, msgs, {2}, b"n1", predicates=[AGE18])
    p2 = present(params, pk, sig, msgs, {2}, b"n2", predicates=[AGE18])
    assert p1.A_prime != p2.A_prime and p1.commitments[1] != p2.commitments[1]