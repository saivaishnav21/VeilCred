"""Sanity-check the real BLS12-381 backend before trusting Phase 2. Run:  python smoke_real_backend.py"""
import time
from veilcred.pairing import BACKEND, G2_GEN, ORDER, hash_to_g1, pairing_product_is_one

assert BACKEND == "real", "unset VEILCRED_BACKEND (or set it to 'real') for this check"
t = time.time()
P = hash_to_g1(b"smoke")
print("hash_to_g1 lands in the prime-order subgroup:", P.in_subgroup(), f"({time.time()-t:.2f}s)")
Q = G2_GEN
t = time.time()
# bilinearity: e(2P, Q) == e(P, 2Q)   <=>   e(2P, Q) * e(-P, 2Q) == 1
print("bilinearity e(2P,Q) = e(P,2Q):", pairing_product_is_one([(2 * P, Q), (-P, 2 * Q)]))
print("non-degenerate  e(P,Q) != 1  :", not pairing_product_is_one([(P, Q)]))
print(f"two-pairing check took {time.time()-t:.2f}s")