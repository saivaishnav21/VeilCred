"""
Benchmarks for the report.

    python benchmark.py            (3 repetitions, medians)
    python benchmark.py --quick    (1 repetition, fewer sizes)

Writes benchmark_results.csv and benchmark_results.md. Numbers are only meaningful on the REAL
backend; the toy backend is just for checking that this script runs.
"""
import csv
import statistics
import sys
import time

from veilcred.bbs import (BBSParams, encode_attribute, keygen, present, sign, verify,
                          verify_presentation, RANGE_BITS)
from veilcred.pairing import BACKEND, G2_GEN, hash_to_g1, pairing_product_is_one
from veilcred.revocation import new_handle

QUICK = "--quick" in sys.argv
REPS = 1 if QUICK else 3
G1_BYTES, SCALAR_BYTES = 48, 32          # compressed BLS12-381 G1 point / scalar (a real serialisation)
AGE18 = (1, "le", 20081122)
CGPA8 = (3, "ge", 80)
rows = []                                # (experiment, parameter, prove_ms, verify_ms, bytes, points, scalars)


def med(fn):
    times, out = [], None
    for _ in range(REPS):
        t = time.perf_counter(); out = fn(); times.append((time.perf_counter() - t) * 1000)
    return statistics.median(times), out


def proof_size(pres):
    pts = 3 + len(pres.commitments) + len(pres.proof.Ts)
    sc = len(pres.proof.responses)
    for pp in pres.predicate_proofs:
        pts += len(pp.proof.Cs) + 2 * len(pp.proof.bit_proofs)
        sc += 4 * len(pp.proof.bit_proofs)
    return pts * G1_BYTES + sc * SCALAR_BYTES, pts, sc


def measure(experiment, label, params, pk, sig, msgs, reveal, predicates=None, revocation=None):
    prove_ms, pres = med(lambda: present(params, pk, sig, msgs, reveal, b"bench", predicates=predicates, revocation=revocation))
    verify_ms, ok = med(lambda: verify_presentation(params, pk, pres, b"bench", require=predicates, revocation=revocation))
    assert ok, "benchmark presentation failed to verify"
    size, pts, sc = proof_size(pres)
    rows.append((experiment, label, round(prove_ms, 1), round(verify_ms, 1), size, pts, sc))
    print(f"  {experiment:<12} {str(label):<10} prove {prove_ms:8.1f} ms   verify {verify_ms:8.1f} ms   {size/1024:7.1f} KB")


print(f"VeilCred benchmarks [backend: {BACKEND}, reps: {REPS}]" + ("   (toy timings are meaningless)" if BACKEND == "toy" else ""))

# ---- A. primitives -------------------------------------------------------------------
print("\nA. primitives")
params = BBSParams(5)
sk, pk = keygen(params)
P = hash_to_g1(b"bench")
msgs5 = [encode_attribute("Alice"), 20030417, encode_attribute("BTech CSE"), 91, new_handle()]
sig5 = sign(params, sk, msgs5)
prim = {
    "G1 scalar mult": med(lambda: 123456789123456789123456789 * P)[0],
    "pairing check (2 pairings)": med(lambda: pairing_product_is_one([(P, G2_GEN), (-P, G2_GEN)]))[0],
    "hash to G1": med(lambda: hash_to_g1(b"bench-hash"))[0],
    "BBS+ sign (5 attrs)": med(lambda: sign(params, sk, msgs5))[0],
    "BBS+ verify (5 attrs)": med(lambda: verify(params, pk, msgs5, sig5))[0],
}
for k, v in prim.items():
    rows.append(("primitive", k, "", round(v, 1), "", "", ""))
    print(f"  {k:<30} {v:8.1f} ms")

# ---- B. vs number of attributes -------------------------------------------------------
print("\nB. presentation vs number of attributes (reveal 1, no predicates, no revocation)")
for L in ((5, 10) if QUICK else (5, 10, 20)):
    p = BBSParams(L); s, k = keygen(p)
    m = [encode_attribute(f"attr{i}") for i in range(L)]
    measure("attributes", L, p, k, sign(p, s, m), m, {0})

# ---- C. vs number of predicates -------------------------------------------------------
print("\nC. presentation vs number of range predicates (5 attributes)")
for label, preds in (("0", []), ("1", [AGE18]), ("2", [AGE18, CGPA8])):
    measure("predicates", label, params, pk, sig5, msgs5, {2}, predicates=preds)

# ---- D. vs blacklist size -------------------------------------------------------------
print("\nD. presentation vs blacklist size (1 range predicate + non-revocation)")
for n in ((0, 5) if QUICK else (0, 5, 10, 20)):
    bl = [new_handle() for _ in range(n)]
    measure("blacklist", n, params, pk, sig5, msgs5, {2}, predicates=[AGE18], revocation=(4, bl))

# ---- write results --------------------------------------------------------------------
with open("benchmark_results.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["experiment", "parameter", "prove_ms", "verify_ms", "proof_bytes", "group_elements", "scalars"])
    w.writerows(rows)

with open("benchmark_results.md", "w", encoding="utf-8") as f:
    f.write(f"# VeilCred benchmarks (backend: {BACKEND}, median of {REPS})\n\n")
    f.write("Proof sizes assume compressed encodings: 48 bytes per G1 point, 32 bytes per scalar.\n\n")
    f.write("## Primitives\n\n| Operation | Time (ms) |\n|---|---|\n")
    for k, v in prim.items():
        f.write(f"| {k} | {v:.1f} |\n")
    for exp, title, unit in (("attributes", "Presentation vs number of attributes", "attributes"),
                             ("predicates", "Presentation vs number of range predicates (32-bit)", "predicates"),
                             ("blacklist", "Presentation vs blacklist size (with 1 range predicate)", "blacklist entries")):
        f.write(f"\n## {title}\n\n| {unit} | Prove (ms) | Verify (ms) | Proof size (KB) | Group elements | Scalars |\n|---|---|---|---|---|---|\n")
        for e, lab, pm, vm, size, pts, sc in rows:
            if e == exp:
                f.write(f"| {lab} | {pm} | {vm} | {size/1024:.1f} | {pts} | {sc} |\n")
print("\nWrote benchmark_results.csv and benchmark_results.md")