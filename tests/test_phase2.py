import copy
from veilcred.bbs import (BBSParams, keygen, sign, verify, present,
                          verify_presentation, encode_attribute, Signature)
from veilcred.pairing import ORDER

FIELDS = ["name", "dob", "degree", "cgpa", "id"]
VALUES = ["Alice", "2003-04-17", "BTech CSE", "9.1", "ID-48213"]


def setup():
    params = BBSParams(5)
    sk, pk = keygen(params)
    msgs = [encode_attribute(v) for v in VALUES]
    return params, sk, pk, msgs, sign(params, sk, msgs)


def test_signature_valid():
    params, sk, pk, msgs, sig = setup()
    assert verify(params, pk, msgs, sig)


def test_signature_rejects_wrong_message_key_or_tampering():
    params, sk, pk, msgs, sig = setup()
    bad = list(msgs); bad[3] = encode_attribute("10.0")
    assert not verify(params, pk, bad, sig)                       # changed CGPA
    _, other_pk = keygen(params)
    assert not verify(params, other_pk, msgs, sig)                # different issuer
    assert not verify(params, pk, msgs, Signature(sig.A, (sig.e + 1) % ORDER, sig.s))


def test_presentation_selective_disclosure():
    params, sk, pk, msgs, sig = setup()
    pres = present(params, pk, sig, msgs, {2}, b"nonce-1")
    assert set(pres.revealed) == {2}
    assert verify_presentation(params, pk, pres, b"nonce-1")


def test_presentation_reveal_nothing_and_everything():
    params, sk, pk, msgs, sig = setup()
    for reveal in (set(), set(range(5))):
        pres = present(params, pk, sig, msgs, reveal, b"n")
        assert verify_presentation(params, pk, pres, b"n")


def test_replay_with_other_nonce_rejected():
    params, sk, pk, msgs, sig = setup()
    pres = present(params, pk, sig, msgs, {2}, b"verifier-A")
    assert not verify_presentation(params, pk, pres, b"verifier-B")


def test_tampered_revealed_value_rejected():
    params, sk, pk, msgs, sig = setup()
    pres = present(params, pk, sig, msgs, {2}, b"n")
    forged = copy.deepcopy(pres)
    forged.revealed[2] = encode_attribute("PhD Physics")
    assert not verify_presentation(params, pk, forged, b"n")


def test_cannot_present_attributes_issuer_never_signed():
    params, sk, pk, msgs, sig = setup()
    lying = list(msgs); lying[3] = encode_attribute("10.0")     # claims CGPA 10.0
    pres = present(params, pk, sig, lying, {3}, b"n")
    assert not verify_presentation(params, pk, pres, b"n")


def test_wrong_issuer_key_rejected():
    params, sk, pk, msgs, sig = setup()
    _, other_pk = keygen(params)
    pres = present(params, pk, sig, msgs, {2}, b"n")
    assert not verify_presentation(params, other_pk, pres, b"n")


def test_unlinkability_presentations_look_unrelated():
    params, sk, pk, msgs, sig = setup()
    p1 = present(params, pk, sig, msgs, {2}, b"n1")
    p2 = present(params, pk, sig, msgs, {2}, b"n2")
    assert p1.A_prime != p2.A_prime and p1.A_bar != p2.A_bar and p1.d != p2.d
    assert p1.A_prime != sig.A and p2.A_prime != sig.A           # signature itself never shown