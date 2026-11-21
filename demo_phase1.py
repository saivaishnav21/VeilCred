import time
from veilcred import *

params = PedersenParams(5)
fields = ["name", "dob", "degree", "cgpa", "id"]
values = ["Alice", "2003-04-17", "BTech CSE", "9.1", "ID-48213"]
attrs = [encode_attribute(v) for v in values]

C, r = params.commit(attrs)
print("Credential commitment C =", C)

nonce = b"verifier-nonce-42"
t = time.time()
d = prove_disclosure(params, attrs, r, C, reveal={2}, context=nonce)
t_prove = time.time() - t
t = time.time()
ok = verify_disclosure(params, C, d, nonce)
t_verify = time.time() - t

print("\nVerifier learns only:", {fields[i]: values[i] for i in d.revealed})
print("Hidden from verifier:", [fields[i] for i in range(5) if i not in d.revealed])
print(f"Proof valid: {ok}  (prove {t_prove*1000:.0f} ms, verify {t_verify*1000:.0f} ms)")
print("Replay with a different nonce accepted?", verify_disclosure(params, C, d, b"other"))
