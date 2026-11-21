import time
from veilcred.bbs import (BBSParams, keygen, sign, present, verify_presentation,
                          encode_attribute)
from veilcred.pairing import BACKEND
from veilcred.revocation import RevocationRegistry, new_handle

print(f"[backend: {BACKEND}]" + ("  <-- INSECURE TOY, algebra only" if BACKEND == "toy" else ""))
REV = 4                                                    # attribute index of the revocation handle
fields = ["name", "dob", "degree", "cgpa(x10)", "rev_handle"]
params = BBSParams(5)
sk, pk = keygen(params)                                    # the university
registry = RevocationRegistry()                            # its public blacklist


def issue(name, dob):
    handle = new_handle()
    msgs = [encode_attribute(name), dob, encode_attribute("BTech CSE"), 91, handle]
    return msgs, sign(params, sk, msgs), handle


alice, bob = issue("Alice", 20030417), issue("Bob", 20030101)
AGE18 = (1, "le", 20081121)


def attempt(who, cred, nonce, blacklist, verifier_list=None):
    msgs, sig, _ = cred
    try:
        pres = present(params, pk, sig, msgs, {2}, nonce, predicates=[AGE18], revocation=(REV, blacklist))
    except ValueError as e:
        return f"{who}: cannot even build a proof ({e})"
    ok = verify_presentation(params, pk, pres, nonce, require=[AGE18],
                             revocation=(REV, verifier_list if verifier_list is not None else blacklist))
    return f"{who}: verifier {'ACCEPTS' if ok else 'REJECTS'}"


print("\n--- blacklist is empty ---")
print(attempt("Alice", alice, b"door-1", registry.snapshot()))
print(attempt("Bob  ", bob, b"door-2", registry.snapshot()))

old_list = registry.snapshot()
registry.revoke(bob[2])                                    # the university revokes Bob's credential
print(f"\n--- Bob's credential revoked (epoch {registry.epoch}, blacklist size {len(registry.snapshot())}) ---")
print(attempt("Alice", alice, b"door-3", registry.snapshot()))
print(attempt("Bob  ", bob, b"door-4", registry.snapshot()))
print("Bob replays an old, pre-revocation list:")
print(attempt("Bob  ", bob, b"door-5", old_list, verifier_list=registry.snapshot()))

print("\n--- cost vs blacklist size (Alice, age>=18 predicate + non-revocation) ---")
print(f"{'blacklist':>10} {'prove (s)':>10} {'verify (s)':>11}")
for n in (0, 5, 10, 20):
    bl = [new_handle() for _ in range(n)]
    t = time.time(); pres = present(params, pk, alice[1], alice[0], {2}, b"bench", predicates=[AGE18], revocation=(REV, bl)); tp = time.time() - t
    t = time.time(); ok = verify_presentation(params, pk, pres, b"bench", require=[AGE18], revocation=(REV, bl)); tv = time.time() - t
    print(f"{n:>10} {tp:>10.2f} {tv:>11.2f}   valid={ok}")