# VeilCred: security analysis

> Educational implementation. Pure Python, not constant-time, not audited. Do not use it to
> protect real data. The arguments below follow standard constructions but were not
> re-proven formally for this code.

## 1. System and roles

| Role | What it does |
|---|---|
| Issuer (university) | Holds secret key `x`, public key `w = x·g2`. Signs 5 attributes (name, date of birth, degree, CGPA, revocation handle) with a BBS+ signature. Publishes a blacklist of revoked handles. |
| Holder | Stores the credential. Builds a presentation: a re-randomised zero-knowledge proof of a valid signature, revealing chosen attributes, proving optional predicates (age >= 18, CGPA >= 8) and non-revocation. |
| Verifier | Sends a fresh nonce, states its policy (required predicates, current blacklist), checks the proof. |

## 2. Threat model

| Adversary | Goal | Capabilities assumed |
|---|---|---|
| Malicious holder | Pass a check they do not satisfy (forge, lie about attributes, fake age, use a revoked credential) | Runs arbitrary code, sees all public parameters |
| Colluding holders | Combine credentials to get one they should not have | Share credentials and signatures with each other |
| Malicious / colluding verifiers | Learn hidden attributes, or recognise the same holder across presentations | Record and compare every presentation they receive |
| Network attacker | Replay or modify presentations | Sees and alters messages |
| Revoked holder | Keep using a credential after revocation | May use stale blacklists |
| Honest-but-curious issuer | Learn more than needed | Sees attributes at issuance |

**Trust assumptions.** The issuer signs only correct attributes and gives each credential a fresh random
128-bit revocation handle. The verifier uses fresh single-use nonces, states its own predicate policy and
fetches the current blacklist. The hash function behaves as a random oracle and the RNG is secure. The
holder's device is not compromised.

**Out of scope.** Side channels and timing, endpoint compromise, network-level anonymity (IP addresses),
key management, credential lending (see limitations), and a networked deployment: the Studio UI runs all
three roles in one process for demonstration.

## 3. Building blocks and assumptions

| Component | Provides | Rests on |
|---|---|---|
| BBS+ signature (BLS12-381) | Unforgeability of credentials | q-SDH assumption (Au-Susilo-Mu); selective-disclosure proof follows Camenisch-Drijvers-Lehmann |
| Pedersen commitments | Perfect hiding; binding | Discrete log between independently generated bases (hash-to-curve, no known relations) |
| Schnorr-style proofs + Fiat-Shamir | Soundness, zero knowledge | Random oracle model; special soundness and honest-verifier ZK of sigma protocols |
| OR-proofs (CDS) | Each committed bit is 0 or 1; verifier cannot tell which branch was real | Same as above |

## 4. Property-by-property argument

**1. Completeness.** An honest holder with a valid credential, satisfying every required predicate and not on
the blacklist, is always accepted. *Evidence:* control case in the attack lab; tests in phases 2-4.

**2. Unforgeability.** A presentation convinces the verifier only if the prover knows a BBS+ signature by the
issuer on an attribute vector consistent with everything disclosed and proven. The pairing check
`e(A', w) = e(Abar, g2)` shows `Abar = x·A'`, which is only possible for a randomised issuer signature, and the
joint proof shows it covers exactly the disclosed values. `A'` = identity is rejected explicitly.
*Evidence:* rogue-issuer, lying, tampering, splicing, degenerate-point and malleability attacks all fail.
*Caveat:* relies on the BBS+ assumption; the rest of the argument is by construction.

**3. Selective disclosure and zero knowledge.** The proof reveals only the chosen attributes. Hidden attributes
enter only as secret exponents of Schnorr proofs whose responses are masked by fresh randomness, and as
Pedersen commitments with fresh blinding. *Caveat:* revealed attributes are revealed in full by design.

**4. Unlinkability.** Every presentation re-randomises the signature (`A' = r1·A`, `d` with fresh `r2`), uses
fresh commitment blinding and fresh proof randomness, so no group element or scalar repeats across
presentations. *Evidence:* link experiment (0 linkable pairs against a baseline where 6/6 same-holder pairs
link). *Caveat:* this is an exact-match experiment, not a formal anonymity proof. Identifying disclosed
attributes (a unique ID number) link presentations by themselves, and the issuer, who saw all attributes at
issuance, can match disclosed values.

**5. Replay and context binding.** The verifier nonce, the issuer key, the disclosed values, the claimed
predicates and a digest of the blacklist are all absorbed into the Fiat-Shamir challenge, so a captured
proof fails under another nonce. *Caveat:* replay at the same verifier is prevented only if the verifier
accepts each nonce once, which is an application duty.

**6. Range predicates.** For `m - t >= 0` the holder commits to each of 32 bits and proves each is 0 or 1;
the verifier checks that the weighted sum of bit commitments equals the commitment to `m - t`. By binding,
the committed value lies in `[0, 2^32)`. A shared secret ties the commitment to the same attribute the
issuer signed, so the holder cannot prove a predicate about a different value. No wrap-around occurs
because `2^32` is far below the group order and attributes are small integers.
*Evidence:* minor cannot build an age proof, wrap-around attack fails, commitment swap fails, weaker-predicate
substitution is blocked by the verifier's `require` policy.

**7. Revocation.** For each blacklisted handle `h` the holder proves knowledge of `y` with
`y·(m - h) = 1`, which exists only if `m != h`. Soundness follows from binding of the commitment.
Privacy follows from zero knowledge and fresh commitments, so the verifier learns only that the handle is
not on the list. The proof covers exactly the verifier's current list, so stale or edited lists fail.
*Evidence:* revoked holder, stale list and list-stripping attacks fail.

## 5. Evidence map

| Property | Tests / attacks |
|---|---|
| Completeness | `test_phase2`, `test_phase3`, `test_phase4`, attack lab control |
| Unforgeability | attack lab: rogue issuer, tamper, lie, splice, degenerate points, malleability |
| Selective disclosure | `test_selective_disclosure_roundtrip`, `test_predicates_verify_and_hide_the_values` |
| Unlinkability | `test_unlinkability_*`, attack lab link experiment |
| Replay resistance | `test_replay_*`, attack lab replay (two cases) |
| Predicate soundness | `test_phase3` suite, `test_a_bit_that_is_not_0_or_1_cannot_be_proven`, wrap-around attack |
| Revocation | `test_phase4` suite, attack lab revocation (three cases) |

## 6. Limitations (stated openly)

- **No holder binding.** Nothing ties a credential to one person, so a holder can lend their whole credential
  to someone else. A "link secret" (a hidden attribute only the holder knows) fixes this, but needs blind issuance.
- **Issuer sees all attributes.** There is no blind issuance, so the issuer could track disclosed values.
- **Revocation cost is linear** in the blacklist size and the blacklist is public. Accumulators or Merkle
  proofs would make it sub-linear.
- **Range proof size is linear in bit-length** (about 9 KB per 32-bit predicate); Bulletproofs would be logarithmic.
- **Verifier duties:** fresh single-use nonces and the current blacklist. Skipping either weakens the guarantees
  (the Studio UI demonstrates what happens if revocation checking is switched off).
- **Implementation:** pure Python (slow), not constant-time, hash-to-curve by try-and-increment, no formal
  verification, no key storage or secure channel, the Studio UI is a single-process demo.
- **Attribute encoding:** strings are hashed to scalars, so a verifier must be given the plaintext and re-encode it.
  Predicates only work on numeric attributes (dates as `YYYYMMDD`, CGPA scaled by 10).

## 7. Future work

Blind issuance with a holder link secret; accumulator-based or Merkle-based revocation; Bulletproofs for range
proofs; a compiled pairing library (e.g. blst) for speed; threshold issuance; alignment with the IETF BBS
signatures draft; device-bound credentials.