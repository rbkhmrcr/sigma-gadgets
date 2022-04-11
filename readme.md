# gk

Here lives the Groth-Kohlweiss sigma protocol for commitments to 0 or 1,
and ring signatures and
'zerocoin scheme', written in Go. The paper and algorithms can be found
[here](https://eprint.iacr.org/2014/764). Signatures are logarithmic in
number of participants, and require only the random oracle model, which is
great for adding to protocols that already exist in ROM (eg blockchains).

## the algo

The Groth-Kohlweiss paper introduces two schemes using their one of many proofs
-- one is a ring signature scheme (not linkable, perfect anonymity), and the other
is a 'zerocoin' scheme, where coins are commitments to serial numbers.

### prep

For n participants in the ring, the sigma protocol has the prover send 4 log n
commitments (which take the form of elliptic curve points) and 3 log n + 1
elements in Zq.  With pedersen commitments, the prover computes 2n log n
exponentiations, and verification takes 2n exponentiations.
multi-exponentiation and batching can be used to reduce the computational
cost.

Pedersen commitments themselves are very simple: using a prime order group G,
and two group elements g & h, given a value m in Zq, and perhaps some
randomness r in Zq, a pedersen commitment is of the form c = g^m h^r.

### deposit stage

The commitment key in our case is just the group and field parameters, and two group
generators, g and h.

Each participant must have committed to a key. This commitment is a pedersen commitment
-- of the form g^x . h^r, with r some randomness, in general. The point here is to show
that one of the commitments opens to zero, so the commitments because g^x . h^0 = g^x.
So just public keys, like the ones people are used to using for ECDSA. Using normal,
non-Edwards curves means we can have a normal key derivation process, and so can use our
stealth address construction as needed. We use sha3 to prevent length extension attacks.

So the senders can form the public keys and submit them, along with the agreed amount of
money, into the mixing contract as expected.

### withdrawal stage

Recipients reveal their serial number and a proof that they know the witness of one of the
commitments to zero that occurred in the deposit stage. Commitments to zero can be thought
of as equivalent to public keys, using the commitment's randomness as private key :)
