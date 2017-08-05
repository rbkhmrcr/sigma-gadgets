package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha3" // we need a hash function that isn't vuln to length extension attacks
	"encoding/hex"
	"errors"
	"fmt"
	secp "github.com/btcsuite/btcd/btcec"
	"io/ioutil"
	"log"
	"math/big"
)

var S *secp.KoblitzCurve

// we need a curve point type so that curve points are just one thing
// as opposed to being representing by their bigint affine coordinates x, y :)
// we should leave off the json bit for prototyping no?

type CurvePoint struct {
	X *big.Int `json:"x"`
	Y *big.Int `json:'y"`
}

// we need public parameters ck = commitment key = g, h
// with g and h so we dont know dl of h wrt g or vice versa
// we actually dont ever need to define g as we can just use .ScalarBaseMult
// but we need to define h

// we could whack a few premade key pairs in here too or not :)

func init() {
	S = secp.S256()
	H, _ = HashToCurve("i am a stupid moron".Bytes()) // check this
}

func prove() {
	N = len(R.PubKeys)
	// n = log base 2 len(R.PubKeys)
	// R hasnt even been defined yet
	// make sure all indices are now in binary and the same length
		var r []*big.Int
		var a []*big.Int
		var s []*big.Int
		var t []*big.Int
		var rho []*big.Int

		var cl []*CurvePoint
		var ca []*CurvePoint
		var cb []*CurvePoint

	for j := 0; j < n; j++ {
		// psa that these arrays dont actually exist?
		// so we need to initialise them? make them slices? i dont get it?
		// should we not replace this with something more compact (yes)
		// do we need to append instead of filling in like this?
		r[j], e := rand.Int(rand.Reader, N)
		check(e)
		a[j], e := rand.Int(rand.Reader, N)
		check(e)
		s[j], e := rand.Int(rand.Reader, N)
		check(e)
		t[j], e := rand.Int(rand.Reader, N)
		check(e)
		rho[k], e := rand.Int(rand.Reader, N)
		check(e)

		// we should probs make these entries in arrays? bleh
		cl[j] := commit(l[j], r[j])
		ca[j] := commit(a[j], s[j])
		cb[j] := commit(l[j] + a[j], t[j])

		k := j - 1
		var product CurvePoint
		for i := 0; i < N; i++ {
		// we need an array of polynomial coefficients to exist
			temp := PubKey[j].ScalarMult(polycoeff[i][k])
			product := product.Add(temp)
		}

		cdk := product.Add(CurvePoint{}.ScalarCaseMult(rhok))

		x := sha3.Sum256("wow so much fun")

		fj := lj * x + aj
		zaj := rj * x + sj
		zbj := rj * (x - fj) + tj

		var sum *big.Int // should this be a pointer?
		for k := 0; k < n; k++ {
			temp := rho[k] * x**k
			sum = sum + temp
		}
		zd := r * x**n - sum

		// return all commitments and fj and zaj and zbj and zdk
	}
}



func commit(a *big.Int, b *big.Int) CurvePoint {
	ha := H.ScalarMult(a)
	gb := CurvePoint{}.ScalarBaseMult(b)
	return ha.Add(gb) // why don't we need to do the interface thing here? how does it know? :o
}

func HashToCurve(s []byte) (CurvePoint, error) {
	q := S.P
	x := big.NewInt(0)
	y := big.NewInt(0)
	z := big.NewInt(0)
	// what is this magical number
	z.SetString("57896044618658097711785492504343953926634992332820282019728792003954417335832", 10)

	// sum256 outputs an array of 32 bytes :) => are we menna use keccak? does this work?
	array := sha3.Sum256(s)
	x = Convert(array[:])
	for true {
		xcubed := new(big.Int).Exp(x, big.NewInt(3), q)
		xcubed7 := new(big.Int).Add(xcubed, big.NewInt(7))
		y.ModSqrt(xcubed7, q)
		y.Set(q)
		y.Add(y, big.NewInt(1))
		y.Rsh(y, 2)
		y.Exp(xcube7, y, q)
		z = z.Exp(y, big.NewInt(2), q)
		posspoint := S.IsOnCurve(x, y)
		if posspoint == true {
			return CurvePoint{x, y}, nil
		}
		x.Add(x, big.NewInt(1))
	}
	return CurvePoint{}, errors.New("no curve point found")
}

// make this not just panic come on nowwww
func check(e error) {
	if e != nil {
		panic(e)
	}
}

// i think this is an actual function from bytes or something?
// this can't not be a thing?
func Convert(data []byte) *big.Int {
	z := new(big.Int)
	z.SetBytes(data)
	return z
}
