import time
from veilcred.bbs import (BBSParams, keygen, sign, verify, present,
                          verify_presentation, encode_attribute)
from veilcred.pairing import BACKEND

print(f"[backend: {BACKEND}]" + ("  <-- INSECURE TOY, algebra only" if BACKEND == "toy" else ""))
fields = ["name", "dob", "degree", "cgpa", "id"]
values = ["Alice", "2003-04-17", "BTech CSE", "9.1", "ID-48213"]

params = BBSParams(len(fields))
sk, pk = keygen(params)                       # the university's key pair
msgs = [encode_attribute(v) for v in values]
sig = sign(params, sk, msgs)                  # issuance
print("Issuer signature valid:", verify(params, pk, msgs, sig))

nonce = b"employer-nonce-42"
t = time.time(); pres = present(params, pk, sig, msgs, {2}, nonce); tp = time.time() - t
t = time.time(); ok = verify_presentation(params, pk, pres, nonce); tv = time.time() - t
print("\nVerifier learns only:", {fields[i]: values[i] for i in pres.revealed})
print(f"Presentation valid: {ok}  (prove {tp:.2f}s, verify {tv:.2f}s)")
print("Replay at another verifier accepted?", verify_presentation(params, pk, pres, b"other"))

pres2 = present(params, pk, sig, msgs, {2}, b"second-verifier")
print("\nUnlinkability: same credential, same disclosed field, two presentations")
print("  A' #1:", pres.A_prime.encode().hex()[-24:], "...")
print("  A' #2:", pres2.A_prime.encode().hex()[-24:], "...  (different -> cannot be linked)")

lie = list(msgs); lie[3] = encode_attribute("10.0")
print("\nForgery attempt (claim CGPA 10.0) accepted?",
      verify_presentation(params, pk, present(params, pk, sig, lie, {3}, nonce), nonce))