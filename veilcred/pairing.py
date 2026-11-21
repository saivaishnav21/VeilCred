"""
Pairing-friendly group backend (BLS12-381) behind a tiny interface.

  real backend (default): py_ecc.optimized_bls12_381  -> genuine cryptography
  toy  backend: set VEILCRED_BACKEND=toy              -> INSECURE, test-only.
                Group elements are just scalars ("exponent representation"), so
                discrete logs are trivial. It lets the protocol *algebra* be
                tested instantly, but proves nothing about security.

Both expose: G1Point, G2Point, ORDER, G2_GEN, hash_to_g1(), pairing_product_is_one().
"""
import hashlib
import os

BACKEND = os.environ.get("VEILCRED_BACKEND", "real")
ORDER = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001

if BACKEND == "real":
    from py_ecc import optimized_bls12_381 as bls

    assert bls.curve_order == ORDER
    _H_EFF = 0xD201000000010001  # G1 effective cofactor (RFC 9380)

    class G1Point:
        order = ORDER
        __slots__ = ("p",)

        def __init__(self, p):
            self.p = p

        @property
        def is_infinity(self):
            return bls.is_inf(self.p)

        def __add__(self, o):
            return G1Point(bls.add(self.p, o.p))

        def __neg__(self):
            return G1Point(bls.neg(self.p))

        def __sub__(self, o):
            return self + (-o)

        def __mul__(self, k):
            k %= ORDER
            return G1Point(bls.Z1) if k == 0 else G1Point(bls.multiply(self.p, k))

        __rmul__ = __mul__

        def __eq__(self, o):
            return isinstance(o, G1Point) and bls.eq(self.p, o.p)

        def __hash__(self):
            return hash(self.encode())

        def in_subgroup(self):
            return bls.is_inf(bls.multiply(self.p, ORDER))

        def on_curve(self):
            """On the curve AND in the prime-order subgroup."""
            if self.is_infinity:
                return True
            return bool(bls.is_on_curve(self.p, bls.b)) and self.in_subgroup()

        def encode(self) -> bytes:
            if self.is_infinity:
                return b"\x00" * 96
            x, y = bls.normalize(self.p)
            return x.n.to_bytes(48, "big") + y.n.to_bytes(48, "big")

    class G2Point:
        order = ORDER
        __slots__ = ("p",)

        def __init__(self, p):
            self.p = p

        def __add__(self, o):
            return G2Point(bls.add(self.p, o.p))

        def __neg__(self):
            return G2Point(bls.neg(self.p))

        def __sub__(self, o):
            return self + (-o)

        def __mul__(self, k):
            k %= ORDER
            return G2Point(bls.Z2) if k == 0 else G2Point(bls.multiply(self.p, k))

        __rmul__ = __mul__

        def __eq__(self, o):
            return isinstance(o, G2Point) and bls.eq(self.p, o.p)

        def encode(self) -> bytes:
            if bls.is_inf(self.p):
                return b"\x00" * 192
            x, y = bls.normalize(self.p)
            out = b""
            for fq2 in (x, y):
                for c in fq2.coeffs:
                    out += int(getattr(c, "n", c)).to_bytes(48, "big")
            return out

    G2_GEN = G2Point(bls.G2)

    def hash_to_g1(label: bytes) -> G1Point:
        """Try-and-increment + cofactor clearing: nobody knows log_G(result)."""
        p = bls.field_modulus
        ctr = 0
        while True:
            x = int.from_bytes(hashlib.sha512(label + ctr.to_bytes(4, "big")).digest(), "big") % p
            rhs = (pow(x, 3, p) + 4) % p
            y = pow(rhs, (p + 1) // 4, p)
            if y * y % p == rhs:
                pt = bls.multiply((bls.FQ(x), bls.FQ(y), bls.FQ.one()), _H_EFF)
                if not bls.is_inf(pt):
                    out = G1Point(pt)
                    assert out.in_subgroup(), "hash_to_g1 produced a point outside the subgroup"
                    return out
            ctr += 1

    def pairing_product_is_one(pairs) -> bool:
        """True iff  prod e(P_i, Q_i) == 1  (P_i in G1, Q_i in G2)."""
        try:  # fast path: one shared final exponentiation
            acc = None
            for P, Q in pairs:
                f = bls.pairing(Q.p, P.p, final_exponentiate=False)
                acc = f if acc is None else acc * f
            return bls.final_exponentiate(acc) == bls.FQ12.one()
        except TypeError:  # older/newer py_ecc without that keyword
            acc = None
            for P, Q in pairs:
                f = bls.pairing(Q.p, P.p)
                acc = f if acc is None else acc * f
            return acc == bls.FQ12.one()

else:  # ---------------- INSECURE toy backend (algebra tests only) ----------------
    class _Toy:
        order = ORDER
        __slots__ = ("v",)

        def __init__(self, v):
            self.v = v % ORDER

        @property
        def is_infinity(self):
            return self.v == 0

        def __add__(self, o):
            return type(self)(self.v + o.v)

        def __neg__(self):
            return type(self)(-self.v)

        def __sub__(self, o):
            return type(self)(self.v - o.v)

        def __mul__(self, k):
            return type(self)(self.v * k)

        __rmul__ = __mul__

        def __eq__(self, o):
            return type(o) is type(self) and self.v == o.v

        def __hash__(self):
            return hash(self.v)

        def on_curve(self):
            return True

        def encode(self) -> bytes:
            return self.v.to_bytes(48, "big")

    class G1Point(_Toy):
        pass

    class G2Point(_Toy):
        pass

    G2_GEN = G2Point(1)

    def hash_to_g1(label: bytes) -> G1Point:
        return G1Point(int.from_bytes(hashlib.sha512(label).digest(), "big") % ORDER)

    def pairing_product_is_one(pairs) -> bool:
        return sum(P.v * Q.v for P, Q in pairs) % ORDER == 0