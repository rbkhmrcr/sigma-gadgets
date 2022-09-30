#!/usr/bin/env sage
from Crypto.Hash import SHA256

def get_poly(n, i, l, a):
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
    return f.list()

# p_{i, k} is the kth coefficient (of which there are n) of the ith polynomial (of which there are N)
def get_poly_product(c, k, poly_dict):
  sum = 1
  for i in range(N):
    sum += poly_dict[i][k] * c[i] # with elliptic curves, we have multiplication not exponentiation
  return sum

def hash(a, b, c, d, e, f, g, h):
  m = SHA256.new(a, b, c, d, e, f, g, h)
  m.digest()

# instantiated with pedersen commitments
def commit(m, r):
  m * gen_g + r * gen_h

def prover(ck, c, provers_index, provers_rand):
  N = len(c)        # gets number of elements in commitment list
  n = N.nbits()     # gets number of bits in list length (eg log(length))

  r = [0] * n
  a = [0] * n
  s = [0] * n
  t = [0] * n
  rho = [0] * n

  l_bits = provers_index.digits(2)
  com_lbits = [0] * n
  com_a = [0] * n
  com_b = [0] * n
  com_d = [0] * n

  for j in range(n):
    r[j] = Fr.random_element()
    a[j] = Fr.random_element()
    s[j] = Fr.random_element()
    t[j] = Fr.random_element()
    rho[j] = Fr.random_element()
    # commit separately to each bit in provers_index, using the rj as randomness
    # commit also to ljaj, using tj as randomness
    com_lbits[j] = commit(l_bits[j], r[j])
    com_a[j] = commit(a[j], s[j])
    com_b[j] = commit(a[j] * l_bits[j], t[j])

  poly_dict = dict( [ (i, getpoly(n, i, provers_index, a)) for i in range(N) ] ) 

  for j in range(n):
    ci_pik = get_poly_product(j, c, poly_dict)
    com_d[j] = ci_pik + commit(0, rho[j])

  challenge = hash(c, com_lbits, com_a, com_b, com_d)
  
  f = [0] * n
  za = [0] * n
  zb = [0] * n
  for j in range(n):
    f[j] = l_bits[j] * challenge + a[j]
    za[j] = r[j] * challenge + s[j]
    zb[j] = r[j] * (challenge - f[j]) + t[j]
  sum = [ ( rho[k] * challenge ** k ) for k in range(n) ]
  zd = provers_randomness * challenge ** n - sum

  return com_lbits, com_a, com_b, com_d, f, za, zb, zd

def verifier(ck, c, com_lbits, com_a, com_b, com_d, f, za, zb, zd):
  N = len(c)
  n = N.nbits()
  challenge = hash(c, com_lbits, com_a, com_b, com_d)
  assert [ ( com_lbits[j] ** challenge * com_a[j] == commit(f[j], za[j] ) for j in range(n) ]
  assert [ ( com_lbits[j] ** (challenge = f[j]) * cb[j] == commit(0, zb[j]) ) for j in range(n) ]

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

  N = 8
  n = 3
  l = 6
  i = 2
  l_bits = [1, 1, 0]
  i_bits = [0, 1, 0]
