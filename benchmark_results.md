# VeilCred benchmarks (backend: real, median of 3)

Proof sizes assume compressed encodings: 48 bytes per G1 point, 32 bytes per scalar.

## Primitives

| Operation | Time (ms) |
|---|---|
| G1 scalar mult | 5.3 |
| pairing check (2 pairings) | 143.6 |
| hash to G1 | 6.3 |
| BBS+ sign (5 attrs) | 24.6 |
| BBS+ verify (5 attrs) | 223.2 |

## Presentation vs number of attributes

| attributes | Prove (ms) | Verify (ms) | Proof size (KB) | Group elements | Scalars |
|---|---|---|---|---|---|
| 5 | 102.3 | 288.5 | 0.5 | 5 | 8 |
| 10 | 154.3 | 289.6 | 0.6 | 5 | 13 |
| 20 | 266.8 | 325.1 | 1.0 | 5 | 23 |

## Presentation vs number of range predicates (32-bit)

| predicates | Prove (ms) | Verify (ms) | Proof size (KB) | Group elements | Scalars |
|---|---|---|---|---|---|
| 0 | 93.2 | 268.3 | 0.5 | 5 | 8 |
| 1 | 808.9 | 1113.7 | 9.1 | 103 | 137 |
| 2 | 1529.7 | 1941.7 | 17.7 | 201 | 266 |

## Presentation vs blacklist size (with 1 range predicate)

| blacklist entries | Prove (ms) | Verify (ms) | Proof size (KB) | Group elements | Scalars |
|---|---|---|---|---|---|
| 0 | 811.9 | 1116.4 | 9.2 | 105 | 138 |
| 5 | 874.2 | 1252.8 | 9.8 | 110 | 148 |
| 10 | 963.6 | 1410.7 | 10.3 | 115 | 158 |
| 20 | 1085.3 | 1692.5 | 11.4 | 125 | 178 |
