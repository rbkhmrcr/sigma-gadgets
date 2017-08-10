package main

import (
	"fmt"
	"golang.org/x/crypto/sha3"
	"math/big"
	"strconv"
)

// Verify is the gk **proof** verification. (contrast with SpendVerify)
func Verify(ring Ring, ringlength int, commitments []CurvePoint, responses []*big.Int, zd *big.Int) bool {
	for i := 0; i < len(commitments); i++ {
		check := Group.IsOnCurve(commitments[i].X, commitments[i].Y)
		if check == false {
			fmt.Println("curve check fails")
			return false
		}
	}

	array := sha3.Sum256([]byte("lots of cool stuff including the commitments"))
	challenge := Convert(array[:])
	ringbin := strconv.FormatInt(int64(ringlength), 2)
	n := int(len(ringbin) + 1)

	for j := 0; j < n; j++ {
		// (x * clj) + caj == commit(fj, zaj)
		// (challenge * commitments[4*j]) + commitments[4*j + 1]
		// == commit(responses[3*j], responses[3*j+1])
		xc := (commitments[4*j]).ScalarMult(challenge)
		lhs := xc.Add(commitments[4*j+1])
		rhs := Commit(responses[3*j], responses[3*j+1])
		if rhs.X.Cmp(lhs.X) != 0 || rhs.Y.Cmp(lhs.Y) != 0 {
			fmt.Println("(x * clj) + caj == commit(fj, zaj) check fails")
			return false
		}

		// ((x - fj) * clj) + cbj == commit(0, zbj)
		// ((challenge - responses[3*j]) * commitments[4*j]) + commitments[4*j+2]
		// == commit(0, responses[3*j+2])
		z := new(big.Int)
		// challenge - responses[3*j]
		xf := z.Sub(challenge, responses[3*j])
		xf = z.Mod(xf, grouporder)
		// ( challenge - responses[3*j] ) * commitments[4*j]
		xfc := (commitments[4*j]).ScalarMult(xf)
		// above + commitments[4*j+2]
		lhs = xfc.Add(commitments[4*j+2])
		rhs = Commit(big.NewInt(0), responses[3*j+2])
		if rhs.X.Cmp(lhs.X) != 0 || rhs.Y.Cmp(lhs.Y) != 0 {
			fmt.Println("((x - fj) * clj) + cbj == commit(0, zbj) check fails")
			return false
		}

		// product from i = 0 to i = N - 1 of ci to the power of product of
		// (product from j = 0 to j = n - 1 of f_{j, i_j})
		// multiplied by product from k = 0 to k = n - 1 of cdk to the power of minus x**k
		// == commit(0, zd)

	}
	return true
}
