# VeilCred attack lab results (backend: real)

| # | Category | Attack | Result | Why |
|---|---|---|---|---|
| 1 | control | Honest adult, not revoked | OK | accepted, as it must be (otherwise the lab would prove nothing) |
| 2 | replay | Replay a captured proof at a different verifier | Defended | proof is bound to the first verifier's nonce |
| 3 | replay | Replay the same proof at the same verifier | Defended | needs verifier-side single-use nonces (an application duty) |
| 4 | forgery | Self-issued credential from a rogue issuer | Defended | pairing check e(A',w)=e(Abar,g2) fails under the real issuer key |
| 5 | forgery | Tamper with a disclosed attribute | Defended | disclosed value is part of the proven statement |
| 6 | forgery | Claim an attribute the issuer never signed (CGPA 10.0) | Defended | no valid signature exists for the altered attribute vector |
| 7 | forgery | Splice an adult's birth date into a minor's credential | Defended | mix-and-match across credentials breaks the signature |
| 8 | forgery | Degenerate points (A' = A-bar = infinity) | Defended | verifier rejects A' = identity (it would pass the pairing check trivially) |
| 9 | forgery | Malleate the proof (change one response scalar) | Defended | Fiat-Shamir equations no longer hold |
| 10 | predicate | Minor tries to prove age >= 18 honestly | Defended | prover cannot even build the proof (difference is negative) |
| 11 | predicate | Minor wraps a negative difference around 2^32 | Defended | bits sum to 2^32-5, not -5, so the sum check fails |
| 12 | predicate | Swap the birth-date commitment for one to a different value | Defended | commitment no longer matches the value the issuer signed |
| 13 | predicate | Minor proves a weaker predicate than the verifier asked for | Defended | verifier policy `require` is not satisfied |
| 14 | revocation | Revoked holder tries to present | Defended | no inverse of (handle - handle) exists, so no proof can be built |
| 15 | revocation | Present against a stale (pre-revocation) blacklist | Defended | proof is bound to the exact list; the verifier's list is newer |
| 16 | revocation | Strip own handle out of the blacklist before proving | Defended | statements are rebuilt from the verifier's own list |
| 17 | privacy | Colluding verifiers try to link presentations of the same holder | Defended | VeilCred: 0 linkable pairs; naive 'show the signature' baseline: 6/6 same-holder pairs linked. (Disclosed attributes can still link if they are identifying.) |
