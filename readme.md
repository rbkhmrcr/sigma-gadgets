# GKringsig

groth-kohlweiss ring signatures in solidity with backend in go!  The paper can be
found [here](https://eprint.iacr.org/2014/764). Signatures are logarithmic in
number of participants, and can be altered from the paper construction to
require only the random oracle model (rather than existing in the common
reference or random string models).

For a more detailed guide to what the contract and client-side code is doing
while this dapp is in use, refer to the section 'the algo' below.
In brief, we have the setup stage (run only by the contract at its deployment
time), the deposit stage, and the withdrawal stage. The senders interact with
the contract in the deposit stage, and the recipients interact with the contract
in the withdrawal stage. What exactly is required in each of these stages is
explained below.


## the algo

the groth-kohlweiss paper introduces two schemes using their one of many proofs
-- one is a ring signature scheme (not linkable, perfect anonymity), and the other
is a 'zerocoin' scheme, where coins are commitments to serial numbers. I _think_
we can use this serial number as a type of linking tag, but we may have to adapt it.
Besides the serial number, the schemes are quite similar. They are also not _too_
different from the original unique ring signature algorithm that we implemented.

### prep

This description is entirely just a rewording of things in the groth-kohlweiss
paper, and so all credit for the beauty of the algorithm goes to them! :)

For n participants in the ring, the sigma protocol has the prover send 4 log n
commitments (which take the form of elliptic curve points) and 3 log n + 1
elements in Zq.  With pedersen commitments, the prover computes 2n log n
exponentiations, and verification takes 2n exponentiations.
multi-exponentiation and batching can be used to reduce the computational
cost, but i'm not smart enough to do this yet.

Pedersen commitments themselves are very simple: using a prime order group G,
and two group elements g & h, given a value m in Zq, and perhaps some
randomness r in Zq, a pedersen commitment is of the form c = g^m h^r.

### deposit stage

The commitment key in our case is just the group and field parameters, and two group
generators, g and h. g and h are both hardcoded (for now? forever?).

Each participant must have committed to a key. This commitment is a pedersen commitment
-- of the form g^x . h^r, with r some randomness, in general. The point here is to show
that one of the commitments opens to zero, so the commitments because g^x . h^0 = g^x.
So just public keys, like the ones people are used to using for ECDSA. Using normal,
non-Edwards curves means we can have a normal key derivation process, and so can use our
stealth address construction as needed. We'll need to use sha3 or keccak256 though, to
defend against potential (low-risk...) length extension attacks.

So the senders can form the public keys and submit them, along with the agreed amount of
money, into the mixing contract as expected.

### withdrawal stage

The recipients run the groth-kohlweiss protocol to generate a 'one of many' proof, which
acts as a ring signature. In the paper, this can be enhanced with a serial number, but
this actually isn't really what we want. What we want is a linkable ring signature, which
is different. Otherwise the state just keeps growing and growing ? People who withdraw
from the contract later have to pay more, but their anonymity set is larger, which makes
sense, i guess.



## user tools

User tools coming soon (TM).

## the api

the contract has 3 functions:
- the constructor
- the deposit phase (commitments to 'public keys' of the recipients)
- the withdrawal phase. Here the recipients prove they have one of the committed
  values (the private keys -- this is a ring signature), and the contract
  verifies the signature and releases the funds if correct.
