package main

import (
	"crypto/rand"
	secp "github.com/btcsuite/btcd/btcec"
	"math/big"
)

type CurvePoint struct {
	X *big.Int
	Y *big.Int
}

// ScalarBaseMult lets us do g.mult(scalar) from btcec with CurvePoints rather than (x, y)
func (c CurvePoint) ScalarBaseMult(x *big.Int) CurvePoint {
	px, py := Group.ScalarBaseMult(x.Bytes())
	return CurvePoint{px, py}
}

// ScalarMult lets us do point.mult(scalar) from btcec with CurvePoints rather than (x, y)
func (c CurvePoint) ScalarMult(x *big.Int) CurvePoint {
	px, py := Group.ScalarMult(c.X, c.Y, x.Bytes())
	return CurvePoint{px, py}
}

// Add lets us do point1.Add(point2) from btcec with CurvePoints rather than (x, y)
func (c CurvePoint) Add(y CurvePoint) CurvePoint {
	px, py := Group.Add(c.X, c.Y, y.X, y.Y)
	return CurvePoint{px, py}
}

var Group = secp.S256()
var grouporder = Group.N
var H = hashtocurve([]byte("I am a stupid moron"))
var ck []CurvePoint

func main() {
}

func Prover(c CurvePoint, m *big.Int, r *big.Int) (CurvePoint, CurvePoint, []*big.Int) {

	// generate a, s, t
	a, e := rand.Int(rand.Reader, grouporder)
	check(e)
	s, e := rand.Int(rand.Reader, grouporder)
	check(e)
	t, e := rand.Int(rand.Reader, grouporder)
	check(e)

	return nil, nil, nil

}

func Verifier(c CurvePoint, ca CurvePoint, cb CurvePoint, responses []*big.Int) bool {
	return false
}

// Commit returns a Pedersen commitment of the form g1**m, g2**r
func Commit(m *big.Int, r *big.Int) CurvePoint {
	gm := CurvePoint{}.ScalarBaseMult(m)
	hr := H.ScalarMult(r)
	return hr.Add(gm)
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
