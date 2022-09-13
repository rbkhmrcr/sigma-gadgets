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
f = [0, 0, 0, 0, 0, 0, 0, 0]
# even though the paper states j is from 1 to n, for accessing we have j = 0 to n-1
# as arrays in sage are 0 indexed

for j in range(int(n)):
  if i_bits[j] == 1:
    if f[i] == 0:
      f[i] = l_bits[j] * x + a[j]
    else:
      f[i] *= l_bits[j] * x + a[j]
  else:
    if f[i] == 0:
      f[i] = (1 - l_bits[j]) * x - a[j]
    else:
      f[i] *= (1 - l_bits[j]) * x - a[j]
print(f)
