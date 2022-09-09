#!/usr/bin/env sage
from Crypto.Hash import SHA256

def __main__():
  # using NIST p256 
  # y^2 = x^3 - 3x + 41058363725152142129326129780047268409114441015993725554835256314039467401291
  # modulo p = 2^256 - 2^224 + 2^192 + 2^96 - 1
  p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
  K = GF(p)
  a = K(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
  b = K(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
  E = EllipticCurve(K, (a, b))
  G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
  E.set_order(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 * 0x1)
  F = Zmod(E.order)
  H = E.random_element()
  R.<x> = F[]
  (ca, cb, f, za, zb) = prover(ck, c, m, r)
  verifier(ck, c, ca, cb, f, za, zb)

def hash(a, b, c, d, e, f, g, h):
  m = SHA256.new(a, b, c, d, e, f, g, h)
  m.digest()

# instantiated with pedersen commitments
def commit(m, r):
  m*G + r*H

# P(ck, c, (m, r))
# a, s, t ← Zn
# ca = Com_ck(a;s) 
# cb = Com_ck(am;t)
# f = mx+a
# za = rx+s
# zb = r(x−f) + t

def prover_zoo(ck, c, m, r):
  a = F.random_element()
  s = F.random_element()
  t = F.random_element()
  ca = commit(a, s)
  cb = commit (a*m, t)
  x = hash(ck, c, a, s, t, ca, cb)
  f = m*x + a
  za = r*x + s
  zb = r * (x-f) + t
  (ca, cb, f, za, zb)

# V(ck, c, ca, cb, f, za, zb)
# Accept if and only if
# ca, cb ∈ C_ck,
# f, za, zb ∈ Zq
# c^x . ca = Com_ck(f; za)
# c^{x−f} . cb = Com_ck(0; zb)
def verifier_zoo(ck, c, ca, cb, f, za, zb):
  assert x*c + ca == commit(f, zb)
  assert (x-f)*c + cb == commit(0, zb)

def prover_oomp(ck, c, m, r):
  if bit_l == bit_j:
    p = p * (x - ma)
  else: 
    p = p * (-x - ma)
