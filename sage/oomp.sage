#!/usr/bin/env sage
from Crypto.Hash import SHA256
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
