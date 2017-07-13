# GKringsig

groth-kohlweiss ring signatures in solidity with backend in go!  paper can be
found [here](https://eprint.iacr.org/2014/764). Signatures are logarithmic in
number of participants, and can be altered from the paper constuction to
require only the random oracle model (rather than existing in the common
reference or random string models).

## the algo

for n participants in the ring, the sigma protocol has the prover send 4 log n
  commitments (which take the form of elliptic curve points) and 3 log n + 1
  elements in Zq.  with pedersen commitments, the prover computes ~n log n
  exponentiations, and verification takes ~n exponentiations.
  multi-exponentiation and batching can be used to reduce the computational
  cost, but i'm not smart enough to do this yet.




## user tools

User tools coming soon (TM).

## the api

the contract has 3 ? functions:
- the constructor
- the deposit phase (commitments to 'public keys' of the recipients)
- the withdrawal phase. here the recipients prove they have one of the commited
  values (the private keys -- this is a ring signature), and the contract
  verifies the signature and releases the funds if correct.
