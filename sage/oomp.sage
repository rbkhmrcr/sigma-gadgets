#!/usr/bin/env sage
from Crypto.Hash import SHA256

def get_poly(n, i, l):
# for each i \in {0, ..., N-1}, k \in {0, ..., n-1}, p_{i,k} is a number, the kth coefficient
# of the polynomial p_i. the polynomial itself is constructed by the product from j = 1 to n
# of f_{j,i_j}, where f_{j,1} = l_j * x + a_j, and f_{j,0} = (1 - l_j) * x - a_j
  i_bits = i.digits(2)
  l_bits = l.digits(2)
  f = 1
  for j in range(n):
    if i_bits[j] == 1:
      f *= l_bits[j] * x + a[j]
    else:
      f *= (1 - l_bits[j]) * x - a[j]
    return f

def hash(a, b, c, d, e, f, g, h):
  m = SHA256.new(a, b, c, d, e, f, g, h)
  m.digest()

# instantiated with pedersen commitments
def commit(m, r):
  m*G + r*H

def prover(ck, c, provers_index, provers_rand):
  N = len(c)        # gets number of elements in commitment list
  n = N.nbits()     # gets number of bits in list length (eg log(length))

  r = [0] * n
  a = [0] * n
  s = [0] * n
  t = [0] * n
  rho = [0] * n

  l_bits = provers_index.digits(2)
  comm_lbits = [0] * n
  comm_a = [0] * n
  comm_lbitsa = [0] * n
  
  for j in range(n):
    r[j] = Fr.random_element()
    a[j] = Fr.random_element()
    s[j] = Fr.random_element()
    t[j] = Fr.random_element()
    rho[j] = Fr.random_element()

    # commit separately to each bit in provers_index, using the rj as randomness
    # commit also to each aj, using sj as randomness
    # commit also to ljaj, using tj as randomness
    # (together these commitments will be used to prove that each bit of provers_index
    # is indeed a 0 or 1)
    comm_lbits[j] = commit(l_bits[j], r[j])
    comm_a[j] = commit(a[j], s[j])
    comm_lbitsa[j] = commit(a[j] * l_bits[j], t[j])

  for i in range(N):
    c[i] = get_poly(n, i, provers_index)

  
  cb = commit (a*m, t)
  x = hash(ck, c, a, s, t, ca, cb)
  f = m*challenge + a
  za = r*challenge + s
  f = [1] * N
  

  zb = 
  (ca, cb, f, za, zb)

def verifier(ck, c, ca, cb, f, za, zb):
  assert x*c + ca == commit(f, zb)
  assert (x-f)*c + cb == commit(0, zb)

def tests():
# Ethereum elliptic curve
  p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
  a = 0
  b = 7
  Fp = GF(p)
  E = EllipticCurve(Fp, [a,b])
  GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
  GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
  g = E(GX,GY)
  n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  h = 1
  r = g.order()
  Fr = GF(r)
  R.<x> = Fr['x']

  # for each i \in {0, ..., N-1}, k \in {0, ..., n-1}, p_{i,k} is a number, the kth coefficient
  # of the polynomial p_i. the polynomial itself is constructed by the product from j = 1 to n
  # of f_{j,i_j}, where f_{j,1} = l_j * x + a_j, and f_{j,0} = (1 - l_j) * x - a_j

  N = 8
  n = 3
  l = 6
  i = 2
  l_bits = [1, 1, 0]
  i_bits = [0, 1, 0]

  a = [Fr.random_element(), Fr.random_element(), Fr.random_element()]
  f = [1, 1, 1, 1, 1, 1, 1, 1]
