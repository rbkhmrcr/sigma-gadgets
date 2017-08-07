package main

import (
	"encoding/hex"
	"encoding/json"
	//	"errors"
	"fmt"
	secp "github.com/btcsuite/btcd/btcec"
	poly "github.com/jongukim/polynomial"
	"io/ioutil"
	//	"math"
	"math/big"
	"strconv"
)

// S is the KoblitzCurve group from btcec ?
var S *secp.KoblitzCurve

// we need a curve point type so that curve points are just one thing
// as opposed to being representing by their bigint affine coordinates x, y :)
// we should leave off the json bit for prototyping no?

// CurvePoint lets us use the bigint affine point rep as one var not two :)
type CurvePoint struct {
	X *big.Int `json:"x"`
	Y *big.Int `json:"y"`
}

// String takes a CurvePoint and converts to a string for pretty printing (& interfacing?)
func (c CurvePoint) String() string {
	return fmt.Sprintf("X: %s, Y: %s", c.X, c.Y)
}

// ScalarBaseMult lets us do g.mult(scalar) from btcec with CurvePoints rather than (x, y)
func (c CurvePoint) ScalarBaseMult(x *big.Int) CurvePoint {
	px, py := S.ScalarBaseMult(x.Bytes())
	return CurvePoint{px, py}
}

// ScalarMult lets us do point.mult(scalar) from btcec with CurvePoints rather than (x, y)
func (c CurvePoint) ScalarMult(x *big.Int) CurvePoint {
	px, py := S.ScalarMult(c.X, c.Y, x.Bytes())
	return CurvePoint{px, py}
}

// Add lets us do point1.Add(point2) from btcec with CurvePoints rather than (x, y)
func (c CurvePoint) Add(y CurvePoint) CurvePoint {
	px, py := S.Add(c.X, c.Y, y.X, y.Y)
	return CurvePoint{px, py}
}

// PrivKeysStr is an array of the private keys as strings
type PrivKeysStr struct {
	Keys []string `json:"privkeys"`
}

// PubKeyStr is a single public key, represented by its affine coords (as strings)
type PubKeyStr struct {
	X string `json:"x"`
	Y string `json:"y"`
}

// RingStr is an array of PubKeyStrs, which are pubkeys as strings
type RingStr struct {
	PubKeys []PubKeyStr `json:"pubkeys"`
}

// PubKey = CurvePoint = affine, bigint representation of EC points
type PubKey struct {
	CurvePoint
}

// Ring is an array of PubKeys (bigint EC point coords). Acts as a list of public keys.
type Ring struct {
	PubKeys []PubKey `json:"pubkeys"`
}

func main() {

	// read in all the private keys
	privkeyfile, err := ioutil.ReadFile("privkeys.json")
	sk := PrivKeysStr{} // because all json files are read in as strings
	if err = json.Unmarshal(privkeyfile, &sk); err != nil {
		panic(err) // we should do better error handling lol
	}

	// read in all the public keys
	keyfile, _ := ioutil.ReadFile("pubkeys.json")
	pk := RingStr{}
	if err = json.Unmarshal(keyfile, &pk); err != nil {
		panic(err)
	}
	pubkeys := convertPubKeys(pk)
	fmt.Println(pubkeys)

	// now we unwrap all the private keys
	for i := 0; i < len(sk.Keys); i++ {
		privbytes, err := hex.DecodeString(sk.Keys[i])
		if err != nil {
			panic(err)
		}
		privbn := new(big.Int).SetBytes(privbytes)
		fmt.Println(privbn)

	}
	// we should have these numbers read in from the files etc etc etc
	randompoly := polynomialbuilder(int64(8), int64(17))

	fmt.Println(randompoly)

}

func polynomialbuilder(signerindex int64, ringlength int64) poly.Poly {

	// this is pretty much just to print and get the bit length, n
	signerindexbin := strconv.FormatInt(signerindex, 2)
	ringbin := strconv.FormatInt(ringlength, 2)
	fmt.Println(signerindexbin)

	// things need to be uint so the bitshifting works
	// len(ringbin) = n
	for j := uint64(0); j < uint64(len(ringbin)); j++ {
		fmt.Println((signerindex >> j) & 0x1)
	}

	// we should make some array of f[i] ?
	// with each f[i] the product over the f[i][j] ?
	// like an array of the final polynomials :)
	// maybe we should keep them all separate.
	// i don't really know yet
	var functionproduct []*poly.Poly

	for i := 0; i < ringlength; i++ {
		for j := uint(0); j < uint(len(ringbin)); j++ {
			if (i >> j & 0x1) == 0 {
				if ((signerindex >> j) & 0x1) == 0 {
					// f = x - aj (aj is bigint so might have to use .minus?)
					functiontemp = poly.NewPolyInts(1, -a[j])
				}
				// otherwise it's just - aj
				functiontemp = poly.NewPolyInts(0, -a[j])
			}
			if (i >> j & 0x1) == 1 {
				if ((signerindex >> j) & 0x1) == 1 {
					// f = x + aj
					functiontemp = poly.NewPolyInts(1, a[j])
				}
				functiontemp = poly.NewPolyInts(0, a[j])
			}
			functionproduct = functiontemp.Multiply(functionproduct)
		}
	}
	return poly.RandomPoly(int64(3), int64(3))
}

func convertPubKeys(rn RingStr) Ring {

	rl := len(rn.PubKeys)
	//fmt.Println("Length : ", rl)
	var ring Ring

	for i := 0; i < rl; i++ {
		var bytesx []byte
		var bytesy []byte
		bytesx, _ = hex.DecodeString(string(rn.PubKeys[i].X))
		bytesy, _ = hex.DecodeString(string(rn.PubKeys[i].Y))
		pubkeyx := new(big.Int).SetBytes(bytesx) // This makes big int
		pubkeyy := new(big.Int).SetBytes(bytesy) // So we can do EC arithmetic
		ring.PubKeys = append(ring.PubKeys, PubKey{CurvePoint{pubkeyx, pubkeyy}})
	}
	return ring
}
