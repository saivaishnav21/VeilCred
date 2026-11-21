import copy
from veilcred import *
from veilcred.group import INFINITY


def test_group_laws():
    assert G.on_curve()
    assert (N * G).is_infinity
    a, b = random_scalar(), random_scalar()
    assert (a + b) * G == a * G + b * G
    assert a * (b * G) == (a * b) * G
    assert G + (-G) == INFINITY


def test_generators_valid_and_distinct():
    p = PedersenParams(4)
    pts = [p.h] + p.g
    assert all(x.on_curve() for x in pts)
    assert len({x.encode() for x in pts}) == len(pts)


def test_commitment_homomorphic_and_opens():
    p = PedersenParams(3)
    m1, m2 = [1, 2, 3], [10, 20, 30]
    C1, r1 = p.commit(m1)
    C2, r2 = p.commit(m2)
    assert p.open_check(C1, m1, r1)
    assert not p.open_check(C1, [1, 2, 4], r1)
    summed, _ = p.commit([11, 22, 33], r1 + r2)
    assert C1 + C2 == summed


def test_hiding_same_message_different_commitments():
    p = PedersenParams(2)
    assert p.commit([5, 6])[0] != p.commit([5, 6])[0]


def test_schnorr_dlog():
    x = random_scalar()
    X = x * G
    tr = lambda: Transcript(b"dlog")
    proof = prove_representation([G], [x], X, tr())
    assert verify_representation([G], X, proof, tr())
    assert not verify_representation([G], (x + 1) * G, proof, tr())


def make_credential():
    p = PedersenParams(5)
    names = ["Alice", "2003-04-17", "BTech CSE", "9.1", "ID-48213"]
    attrs = [encode_attribute(v) for v in names]
    C, r = p.commit(attrs)
    return p, attrs, r, C


def test_selective_disclosure_roundtrip():
    p, attrs, r, C = make_credential()
    d = prove_disclosure(p, attrs, r, C, reveal={2}, context=b"nonce-123")
    assert set(d.revealed) == {2}                       # only the degree is revealed
    assert verify_disclosure(p, C, d, b"nonce-123")


def test_reveal_nothing_and_everything():
    p, attrs, r, C = make_credential()
    for reveal in (set(), set(range(5))):
        d = prove_disclosure(p, attrs, r, C, reveal, b"n")
        assert verify_disclosure(p, C, d, b"n")


def test_wrong_context_rejected_replay():
    p, attrs, r, C = make_credential()
    d = prove_disclosure(p, attrs, r, C, {2}, b"verifier-A-nonce")
    assert not verify_disclosure(p, C, d, b"verifier-B-nonce")


def test_tampered_disclosed_value_rejected():
    p, attrs, r, C = make_credential()
    d = prove_disclosure(p, attrs, r, C, {2}, b"n")
    forged = copy.deepcopy(d)
    forged.revealed[2] = encode_attribute("PhD Physics")
    assert not verify_disclosure(p, C, forged, b"n")


def test_cannot_disclose_attribute_not_committed():
    p, attrs, r, C = make_credential()
    lying = list(attrs)
    lying[3] = encode_attribute("10.0")        # prover lies about CGPA
    d = prove_disclosure(p, lying, r, C, {3}, b"n")
    assert not verify_disclosure(p, C, d, b"n")


def test_proofs_are_randomised():
    p, attrs, r, C = make_credential()
    d1 = prove_disclosure(p, attrs, r, C, {2}, b"n")
    d2 = prove_disclosure(p, attrs, r, C, {2}, b"n")
    assert d1.proof.T != d2.proof.T
