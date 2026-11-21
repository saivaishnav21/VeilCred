"""Run the VeilCred attack lab:  python attack_lab.py   (writes attack_report.md and attack_report.json)"""
import json
import sys

from veilcred.attacks import run_all
from veilcred.pairing import BACKEND

if BACKEND == "toy":
    print("WARNING: toy backend is insecure and for algebra tests only; run with the real backend.\n")

results = run_all()
print(f"VeilCred attack lab  [backend: {BACKEND}]\n")
print(f"{'#':>2}  {'category':<11} {'result':<9} {'time':>6}  attack")
print("-" * 92)
for i, r in enumerate(results, 1):
    label = ("OK" if r.category == "control" else "DEFENDED") if r.passed else "BROKEN"
    print(f"{i:>2}  {r.category:<11} {label:<9} {r.seconds:>5.1f}s  {r.name}")
    print(f"{'':>38}-> {r.note}")
failed = [r for r in results if not r.passed]
print("-" * 92)
print(f"{len(results) - len(failed)}/{len(results)} behaved correctly" + (f"; FAILED: {[r.name for r in failed]}" if failed else ""))

with open("attack_report.md", "w", encoding="utf-8") as f:
    f.write(f"# VeilCred attack lab results (backend: {BACKEND})\n\n")
    f.write("| # | Category | Attack | Result | Why |\n|---|---|---|---|---|\n")
    for i, r in enumerate(results, 1):
        label = ("OK" if r.category == "control" else "Defended") if r.passed else "BROKEN"
        f.write(f"| {i} | {r.category} | {r.name} | {label} | {r.note} |\n")
with open("attack_report.json", "w", encoding="utf-8") as f:
    json.dump([r.__dict__ for r in results], f, indent=2)
print("\nWrote attack_report.md and attack_report.json")
sys.exit(1 if failed else 0)