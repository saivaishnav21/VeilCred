import time
from datetime import date
from veilcred.bbs import (BBSParams, keygen, sign, present, verify_presentation,
                          encode_attribute, RANGE_BITS)
from veilcred.pairing import BACKEND

print(f"[backend: {BACKEND}]" + ("  <-- INSECURE TOY, algebra only" if BACKEND == "toy" else ""))
today = date.today()
cutoff = (today.year - 18) * 10000 + today.month * 100 + today.day   # dob <= cutoff  <=>  age >= 18
AGE18 = (1, "le", cutoff)
CGPA8 = (3, "ge", 80)                                                 # CGPA x10, so 8.0 -> 80

fields = ["name", "dob", "degree", "cgpa(x10)", "id"]
params = BBSParams(5)
sk, pk = keygen(params)                                               # the university


def issue(name, dob, cgpa):
    msgs = [encode_attribute(name), dob, encode_attribute("BTech CSE"), cgpa, encode_attribute("ID-" + name)]
    return msgs, sign(params, sk, msgs)


alice_msgs, alice_sig = issue("Alice", 20030417, 91)
print(f"\nPolicy: prove age >= 18 (dob <= {cutoff}) and CGPA >= 8.0, show only the degree")
nonce = b"club-door-nonce-7"
t = time.time()
pres = present(params, pk, alice_sig, alice_msgs, {2}, nonce, predicates=[AGE18, CGPA8])
tp = time.time() - t
t = time.time()
ok = verify_presentation(params, pk, pres, nonce, require=[AGE18, CGPA8])
tv = time.time() - t
print("\nVerifier sees revealed attributes :", {fields[i]: "BTech CSE" for i in pres.revealed})
print("Verifier sees proven predicates   :", [f"{fields[p.index]} {p.op} {p.threshold}" for p in pres.predicate_proofs])
print("Verifier does NOT see             : name, exact dob, exact CGPA, id")
print(f"Valid: {ok}   (prove {tp:.2f}s, verify {tv:.2f}s, {RANGE_BITS}-bit range proofs)")
n_elems = sum(len(p.proof.Cs) * 3 for p in pres.predicate_proofs)
print(f"Range-proof size: ~{n_elems} group elements for {len(pres.predicate_proofs)} predicates")

print("\nReplay at another verifier accepted?", verify_presentation(params, pk, pres, b"other-door", require=[AGE18, CGPA8]))

bob_msgs, bob_sig = issue("Bob", 20100101, 91)
try:
    present(params, pk, bob_sig, bob_msgs, {2}, nonce, predicates=[AGE18])
    print("Bob (born 2010) produced an age proof?! (this should not happen)")
except ValueError as e:
    print("Bob (born 2010) cannot prove age >= 18:", e)