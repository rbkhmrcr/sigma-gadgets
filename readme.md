# GKringsig

groth-kohlweiss ring signatures in solidity with backend in go!  paper can be
found [here](https://eprint.iacr.org/2014/764). Signatures are logarithmic in
number of participants, and can be altered from the paper constuction to
require only the random oracle model (rather than existing in the common
reference or random string models).

## the algo

this description is entirely just a reqording of things in the groth-kohlweiss
paper, and so all credit for the beauty of the algorithm goes to them! :)

for n participants in the ring, the sigma protocol has the prover send 4 log n
commitments (which take the form of elliptic curve points) and 3 log n + 1
elements in Zq.  with pedersen commitments, the prover computes ~n log n
exponentiations, and verification takes ~n exponentiations.
multi-exponentiation and batching can be used to reduce the computational
cost, but i'm not smart enough to do this yet.

pedersen commitments themselves are very simple. using a prime order group G, and
two group elements g & h, given a value m in Zq, and perhaps some randomness r in Zq,
a pedersen commitment is of the form c = g^m h^r.





## user tools

User tools coming soon (TM).

## the api

the contract has 3 ? functions:
- the constructor
- the deposit phase (commitments to 'public keys' of the recipients)
- the withdrawal phase. here the recipients prove they have one of the commited
  values (the private keys -- this is a ring signature), and the contract
  verifies the signature and releases the funds if correct.
