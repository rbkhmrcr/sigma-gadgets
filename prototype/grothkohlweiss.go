package main

import (
	"bytes"
	"crypto/rand"
	"golang.org/x/crypto/sha3"
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

func (c CurvePoint) String() string {
	return fmt.Sprintf("X: %s, Y: %s", c.X, c.Y)
}

func (c CurvePoint) ScalarBaseMult(x *big.Int) CurvePoint {
	px, py := Group.ScalarBaseMult(x.Bytes())
	return CurvePoint{px, py}
}

func (c CurvePoint) ScalarMult(x *big.Int) CurvePoint {
	px, py := Group.ScalarMult(c.X, c.Y, x.Bytes())
	return CurvePoint{px, py}
}

func (c CurvePoint) Add(y CurvePoint) CurvePoint {
	px, py := Group.Add(c.X, c.Y, y.X, y.Y)
	return CurvePoint{px, py}
}


type PubKeyStr struct {
	X string `json:"x"`
	Y string `json:"y"`
}

type RingStr struct {
	PubKeys []PubKeyStr `json:"pubkeys"`
}

type PrivKeysStr struct {
	Keys []string `json:"privkeys"`
}

type PubKey struct {
	CurvePoint
}

type Ring struct {
	PubKeys []PubKey `json:"pubkeys"`
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

func main() {
args := os.Args[1:]
	privkeyfile, err := ioutil.ReadFile("privkeys.json")
	sk := PrivKeysStr{}
	if err = json.Unmarshal(privkeyfile, &sk); err != nil {
		panic(err)
	}
	keyfile, _ := ioutil.ReadFile("pubkeys.json")
	rn := RingStr{}
	if err = json.Unmarshal(keyfile, &rn); err != nil {
		panic(err)
	}
	pubkeyring := convertPubKeys(rn)
	// we need to find out which public key the private key corresponds to.

	for i := 0; i < len(pk.Keys); i++ {
		privbytes, err := hex.DecodeString(sk.Keys[i])
		if err != nil {
			panic(err)
		}
		privBN := new(big.Int).SetBytes(privbytes)
		sign(pubkeyring, privBN)
	}
}



func prove() {

	N = len(R.PubKeys)
	n = int(math.Log2(N))
	if 2**n != N {
		n = n + 1
	}

	// R hasnt even been defined yet
	// make sure all indices are now in binary and the same length
	randoms := make([]*big.Int, len(5*n))
	commitments := make([]*CurvePoint, len(5*n))

	// should these be pointers or no? whats the dealio?

	for j := 0; j < n; j++ {
		// psa that these arrays dont actually exist?
		// so we need to initialise them? make them slices? i dont get it?
		// should we not replace this with something more compact (yes)
		// do we need to append instead of filling in like this?
		rj, e := rand.Int(rand.Reader, N)
		check(e)
		randoms = append(randoms, rj)
		// so
		aj, e := rand.Int(rand.Reader, N)
		check(e)
		randoms = append(randoms, aj)
		sj, e := rand.Int(rand.Reader, N)
		check(e)
		randoms = append(randoms, sj)
		tj, e := rand.Int(rand.Reader, N)
		check(e)
		randoms = append(randoms, tj)
		rhok, e := rand.Int(rand.Reader, N)
		check(e)
		randoms = append(randoms, rhok)

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

func verify() bool {

for j := 0; j < n; j++ {

		lhs := ca[j].Add(cl[j].ScalarMult(x))
		rhs := commit(f[j], za[j])
		if lhs != rhs {
			return false
		}

		lhs = cb[j].Add(cl[j].ScalarMult(x - f[j]))
		rhs = CurvePoint{}.ScalarBaseMult(zb[j])
		if lhs != rhs {
		return false
		}

		var fproduct *big.Int
		var cproduct *CurvePoint
		for i := 0; i < N; i++ {
		// make i into binary here
			for j := 0; j < n; j++ {
				fproduct = fproduct * ftbd(j, i[j])
				//ftbd as is function to be defined lol
				//ftbd is fj when i[j] = 1 and x - fj when i[j] = 0
			}

			cproduct = cproduct.Add(c[i].ScalarMult(fproduct)) // this is lhs part 1
		}

		var cdkproduct *CurvePoint
		for k := 0; k < n; k++ {
			cdkproduct = cdkproduct.Add(cd[k].ScalarMult(-x**k))
		}

		lhs = cproduct.Add(cdkproduct)
		rhs = CurvePoint{}.ScalarBaseMult(zd)
		if lhs != rhs {
			return false
		}
		return true
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
