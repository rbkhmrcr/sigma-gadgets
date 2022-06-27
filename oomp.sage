# https://eprint.iacr.org/2014/764.pdf 

# a Σ-protocol for knowledge of one out of N commitments c_0,...,c_{N−1} being
# a commitment to 0. More precisely, we will give a Σ-protocol for the relation
# R = ck,(c0,...,cN−1),(l,r) ∀i:ci ∈ C ck ∧ l ∈ {0,...,N−1} ∧ r ∈ Zq ∧ cl = Com
# ck(0;r).  To explain the idea behind the Σ-protocol let us for simplicity
# assume the commitment scheme is perfectly binding such that each commitment
# has a unique committed value.  Saying that one of the commitments contains 0
# is equivalent to saying there exists an index l such that product(ci)^(δil)
# is a commitment to 0, where δil is Kronecker’s delta, i.e., δll = 1 and δil =
# 0 for i ̸= l. i=0 i We can always copy some commitments in the statement, so
# let us without loss of generality assume N = 2n. 

# Writing i = i1 ...in and l = l1 ...ln in binary, we have δil = product(δijlj)
# so we can reformulate what we want to prove as product(ci)^product(δijlj)
# being a commitment to 0.  i=0 i The prover will start by making commitments
# cl1 , . . . , cln to the bits l1, . . . , ln. She then engages in n parallel
# Σ-protocols as described in Sect. 2.3 to demonstrate knowledge of openings of
# these commitments to values lj ∈ {0,1}.  In the Σ-protocols for lj ∈ {0,1}
# the prover reveals f1,...,fn of the form fj = ljx+aj. 

# Let fj,1 = fj = ljx + aj = δ1ljx + aj 
# and fj,0 = x − fj = (1−lj)x − aj = δ0lj x − aj. 

# Then we have for each i that product(fj,ij) is a polynomial of the form pi(x)
# = product(δijljx) + sum(p_{i,k}x^k) = δil x^n + sum(p_{i,k}x^k). (1) The idea
# is now that the prover in the initial message will send commitments c_{d_0},
# ..., c_{d_{n−1}} that will be used to cancel out the low order coefficients
# corresponding to x_0, ..., x_{n−1}. Meanwhile the high order coefficient for
# xn will guarantee the commitment cl can be opened to 0. The verifier checks
# that product(c_i^(product(f_{j,i_j}))) . product(c_{dk}^{-x^k}) is a
# commitment to 0, which by the Schwartz-Zippel lemma has negligible
# probability of being true unless indeed cl is a commitment to 0.  Fig. 2
# gives the full Σ-protocol (G, P, V) for R with G being the key generation
# algorithm for the commitment scheme and P, V running on ck←G(1λ), c_0, ...,
# c_{N−1} ∈ C_{ck}, l ∈ {0,...,N−1} and r ∈ Zq such that cl = Com_{ck}(0;r). 
