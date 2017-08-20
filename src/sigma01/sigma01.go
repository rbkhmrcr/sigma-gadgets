package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"golang.org/x/crypto/sha3"
	"math/big"
)

// lemme start with a caveat/explanation that most of this will disappear when
// stuff from a diff folder gets made into a package :)

// CurvePoint = (x, y)
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

// Group = secp256k1
var Group = btcec.S256()
var grouporder = Group.N

// H is the second generator
var H, _ = hashtocurve([]byte("I am a stupid moron"))

func main() {
	var ck []CurvePoint
	ck = append(ck, CurvePoint{Group.Gx, Group.Gy})
	ck = append(ck, H)
}

// Prover creates a (SHVZK) proof that a commitment opens to 0 or 1
func Prover(ck []CurvePoint, c CurvePoint, m *big.Int, r *big.Int) (CurvePoint, CurvePoint, *big.Int, *big.Int, *big.Int) {

	// generate a, s, t
	a, e := rand.Int(rand.Reader, grouporder)
	check(e)
	s, e := rand.Int(rand.Reader, grouporder)
	check(e)
	t, e := rand.Int(rand.Reader, grouporder)
	check(e)

	// commitments to a with s and am with t :)
	ca := commit(a, s)
	am := new(big.Int).Mul(a, m)
	cb := commit(am, t)

	xdigest := sha3.Sum256([]byte("something to do with the above commitments should go here"))
	x := convert(xdigest[:])

	f := new(big.Int).Mul(m, x)
	f.Mod(f, grouporder)
	f.Add(f, a)
	f.Mod(f, grouporder)

	za := new(big.Int).Mul(r, x)
	za.Mod(za, grouporder)
	za.Add(za, s)
	za.Mod(za, grouporder)

	zb := new(big.Int).Sub(x, f)
	zb.Mul(zb, r) // can we use zb.Mul(zb) like this ? :/
	zb.Mod(zb, grouporder)
	zb.Add(zb, t)
	zb.Mod(zb, grouporder)

	return ca, cb, f, za, zb

}

// Verifier checks the above created proof that a commitment opens to 0 or 1
func Verifier(ck []CurvePoint, c CurvePoint, ca CurvePoint, cb CurvePoint, f *big.Int, za *big.Int, zb *big.Int) bool {

	xdigest := sha3.Sum256([]byte("something to do with the above commitments should go here"))
	x := convert(xdigest[:])

	cx := c.ScalarMult(x)
	lhs := cx.Add(ca)
	rhs := commit(f, za)
	if rhs.X.Cmp(lhs.X) != 0 || rhs.Y.Cmp(lhs.Y) != 0 {
		fmt.Println("(x * c) + ca == commit(f, za) check fails")
		return false
	}

	xf := new(big.Int).Sub(x, f)
	xf.Mod(xf, grouporder)
	cxf := c.ScalarMult(xf)
	lhs = cxf.Add(cb)
	rhs = commit(big.NewInt(0), zb)
	if rhs.X.Cmp(lhs.X) != 0 || rhs.Y.Cmp(lhs.Y) != 0 {
		fmt.Println("((x - f)* c) + cb == commit(0, zb) check fails")
		return false
	}

	return true
}

// Commit returns a Pedersen commitment of the form g1**m, g2**r
func commit(m *big.Int, r *big.Int) CurvePoint {
	gm := CurvePoint{}.ScalarBaseMult(m)
	hr := H.ScalarMult(r)
	return hr.Add(gm)
}

// HashToCurve takes a byteslice and returns a CurvePoint (whose DL remains unknown!)
func hashtocurve(s []byte) (CurvePoint, error) {
	q := Group.P
	x := big.NewInt(0)
	y := big.NewInt(0)
	z := big.NewInt(0)
	// what is this magical number
	z.SetString("57896044618658097711785492504343953926634992332820282019728792003954417335832", 10)

	array := sha3.Sum256(s)
	x = convert(array[:])
	for true {
		xcubed := new(big.Int).Exp(x, big.NewInt(3), q)
		xcubed7 := new(big.Int).Add(xcubed, big.NewInt(7))
		y.ModSqrt(xcubed7, q)
		y.Set(q)
		y.Add(y, big.NewInt(1))
		y.Rsh(y, 2)
		y.Exp(xcubed7, y, q)
		z = z.Exp(y, big.NewInt(2), q)
		posspoint := Group.IsOnCurve(x, y)
		if posspoint == true {
			return CurvePoint{x, y}, nil
		}
		x.Add(x, big.NewInt(1))
	}
	return CurvePoint{}, errors.New("no curve point found")
}

func convert(data []byte) *big.Int {
	z := new(big.Int)
	z.SetBytes(data)
	return z
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
