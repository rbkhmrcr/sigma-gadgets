# GKringsig

groth-kohlweiss ring signatures in solidity with backend in go!  paper can be
found [here](https://eprint.iacr.org/2014/764). Signatures are logarithmic in
number of participants, and can be altered from the paper constuction to
require only the random oracle model (rather than existing in the common
reference or random string models).

## the algo

### prep

this description is entirely just a reqording of things in the groth-kohlweiss
paper, and so all credit for the beauty of the algorithm goes to them! :)

for n participants in the ring, the sigma protocol has the prover send 4 log n
commitments (which take the form of elliptic curve points) and 3 log n + 1
elements in Zq.  with pedersen commitments, the prover computes 2n log n
exponentiations, and verification takes 2n exponentiations.
multi-exponentiation and batching can be used to reduce the computational
cost, but i'm not smart enough to do this yet.

pedersen commitments themselves are very simple. using a prime order group G,
and two group elements g & h, given a value m in Zq, and perhaps some
randomness r in Zq, a pedersen commitment is of the form c = g^m h^r.

### deposit stage

the commitment key in our case is just the group and field parameters, and two group
generators, g and h. g and h are both hardcoded (for now? forever?).

each participant must have committed to a key. this commitment is a pedersen commitment
-- of the form g^x . h^r, with r some randomness, in general. The point here is to show
that one of the commitments opens to zero, so the commitments because g^x . h^0 = g^x.
So just public keys, like the ones people are used to using for ECDSA. Using normal,
non-Edwards curves means we can have a normal key derivation process, and so can use our
stealth address construction as needed. We'll need to use sha3 or keccak256 though, to
defend against potential (low-risk...) length extension attacks.

so the senders can form the public keys and submit them, along with the agreed amount of
money, into the mixing contract as expected.

### withdrawal stage

the recipients run the groth-kohlweiss protocol to generate a 'one of many' proof, which
acts as a ring signature. in the paper, this can be enhanced with a serial number, but
this actually isn't really what we want. what we want is a linkable ring signature, which
is different. otherwise the state just keeps growing and growing ? people who withdraw
from the contract later have to pay more, but their anonymity set is larger, which makes
sense, i guess.



## user tools

User tools coming soon (TM).

## the api

the contract has 3 ? functions:
- the constructor
- the deposit phase (commitments to 'public keys' of the recipients)
- the withdrawal phase. here the recipients prove they have one of the commited
  values (the private keys -- this is a ring signature), and the contract
  verifies the signature and releases the funds if correct.
