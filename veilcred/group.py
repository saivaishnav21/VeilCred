"""
Prime-order elliptic-curve group (secp256k1), implemented from scratch.

Phase 1 uses secp256k1 because it is prime-order (cofactor 1) and has no
dependencies. Phase 2 (BBS+) needs a pairing-friendly curve, so a BLS12-381
backend with the same interface will be added then. Everything in sigma.py /
pedersen.py only uses the interface below, so it will carry over unchanged.
"""
import hashlib
import secrets

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

ORDER = N  # scalars live in Z_N


class Point:
    """Affine point on y^2 = x^3 + 7. (None, None) is the point at infinity."""
    __slots__ = ("x", "y")

    def __init__(self, x=None, y=None):
        self.x, self.y = x, y

    @property
    def is_infinity(self):
        return self.x is None

    def __eq__(self, other):
        return isinstance(other, Point) and self.x == other.x and self.y == other.y

    def __hash__(self):
        return hash((self.x, self.y))

    def __neg__(self):
        return self if self.is_infinity else Point(self.x, (-self.y) % P)

    def __add__(self, other):
        if self.is_infinity:
            return other
        if other.is_infinity:
            return self
        if self.x == other.x:
            if (self.y + other.y) % P == 0:
                return INFINITY
            lam = 3 * self.x * self.x * pow(2 * self.y, -1, P) % P
        else:
            lam = (other.y - self.y) * pow(other.x - self.x, -1, P) % P
        x3 = (lam * lam - self.x - other.x) % P
        y3 = (lam * (self.x - x3) - self.y) % P
        return Point(x3, y3)

    def __sub__(self, other):
        return self + (-other)

    def __mul__(self, k):
        """Scalar multiplication (double-and-add)."""
        k %= N
        result, addend = INFINITY, self
        while k:
            if k & 1:
                result = result + addend
            addend = addend + addend
            k >>= 1
        return result

    __rmul__ = __mul__

    def on_curve(self):
        if self.is_infinity:
            return True
        return (self.y * self.y - self.x ** 3 - 7) % P == 0

    def encode(self) -> bytes:
        """33-byte compressed encoding (used for hashing into transcripts)."""
        if self.is_infinity:
            return b"\x00" * 33
        return bytes([2 + (self.y & 1)]) + self.x.to_bytes(32, "big")

    def __repr__(self):
        return "Point(INF)" if self.is_infinity else f"Point({self.encode().hex()[:12]}...)"


INFINITY = Point()
G = Point(GX, GY)


def random_scalar() -> int:
    """Uniform non-zero scalar in Z_N."""
    return secrets.randbelow(N - 1) + 1


def hash_to_point(label: bytes) -> Point:
    """
    Try-and-increment hash to curve. Nobody knows log_G of the result, which is
    exactly what Pedersen binding needs ("nothing up my sleeve" generators).
    """
    ctr = 0
    while True:
        digest = hashlib.sha256(label + ctr.to_bytes(4, "big")).digest()
        x = int.from_bytes(digest, "big") % P
        rhs = (pow(x, 3, P) + 7) % P
        y = pow(rhs, (P + 1) // 4, P)  # valid since P = 3 mod 4
        if y * y % P == rhs:
            if y & 1:
                y = P - y
            return Point(x, y)
        ctr += 1


def sum_points(points):
    acc = INFINITY
    for p in points:
        acc = acc + p
    return acc
