# VeilCred

A privacy-preserving digital credential system: prove a claim about yourself
(degree, age, eligibility) without revealing the rest of your identity.

Built for an Applied Cryptography course project.

## Features
- Pedersen commitments and selective disclosure (done)
- BBS+ anonymous credentials (done)
- Range proofs(done), unlinkability, privacy-preserving revocation (planned)

## Run it
    python -m venv .venv
    .venv\Scripts\activate
    pip install pytest py_ecc
    python demo_phase1.py
    python demo_phase2.py
    python demo_phase3.py
    python -m pytest -q

## Disclaimer
Educational implementation. It is not constant-time or audited and must not
be used to protect real data.