package main

import (
	"crypto/rand"
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

// S is KoblitzCurve from btcec
var S *secp.KoblitzCurve
var group = secp.S256()
var grouporder = group.N

// we need a curve point type so that curve points are just one thing
// as opposed to being representing by their bigint affine coordinates x, y :)

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
	// len(sk.Keys) is a silly hacky way of getting the ring size.
	// it shoud defs be changed irl
	var polyarray []poly.Poly
	for i := 0; i < len(sk.Keys); i++ {
		randompoly := polynomialbuilder(int(3), len(sk.Keys), int(i))
		// we build polyarray like p[0][k], p[1][k], ...
		polyarray = append(polyarray, randompoly)
	}
	fmt.Println(polyarray)

}

func polynomialbuilder(signerindex int, ringsize int, i int) poly.Poly {

	// this is just to print and get the bit length, n
	// signerindexbin := strconv.FormatInt(int64(signerindex), 2)
	ringbin := strconv.FormatInt(int64(ringsize), 2)
	var product poly.Poly
	var polyarray []poly.Poly
	// the products of functions defined by each i form distinct polynomials (one per i)
	// this polynomial will have degree max bitlength(ringlength)

	// things need to be uint so the bitshifting works
	// len(ringbin) = n
	// ------------------------------------------------------------------------------
	// is it gonna cause problems that we're running 0 -> n - 1 rather than 1 -> n :(

	// j is the bit index.
	// the functions defined in this bit get multiplied together to form the poly above
	for j := uint(0); j < uint(len(ringbin)); j++ {

		var functiontemp poly.Poly
		aj, e := rand.Int(rand.Reader, grouporder)
		check(e)
		z, e := rand.Int(rand.Reader, grouporder)
		check(e)

		// we compare i (the current index) to l (the signer index), bitwise
		if (i >> j & 0x1) == 0 {
			if ((signerindex >> j) & 0x1) == 0 {
				// f = x - aj
				functiontemp = append(functiontemp, z.ModInverse(aj, grouporder))
				functiontemp = append(functiontemp, big.NewInt(1))
			}
			if ((signerindex >> j) & 0x1) == 1 {
				// otherwise it's just - aj
				functiontemp = append(functiontemp, z.ModInverse(aj, grouporder))
				functiontemp = append(functiontemp, big.NewInt(0))
			}
		}

		if (i >> j & 0x1) == 1 {
			if ((signerindex >> j) & 0x1) == 1 {
				// f = x + aj
				// this mod is super redundant
				functiontemp = append(functiontemp, z.Mod(aj, grouporder))
				functiontemp = append(functiontemp, big.NewInt(1))
			}
			if ((signerindex >> j) & 0x1) == 0 {
				// otherwise it's just aj
				// this mod is super redundant
				functiontemp = append(functiontemp, z.Mod(aj, grouporder))
				functiontemp = append(functiontemp, big.NewInt(0))
			}
		}

		if j == 0 {
			// i should do this in some prettier way hey?
			product = poly.NewPolyInts(0, 0, 0, 0, 0)
			product = functiontemp
		} else {
			product = product.Mul(functiontemp, grouporder)
		}
	}

	polyarray = append(polyarray, product)
	fmt.Println(polyarray)

	return product

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

func check(e error) {
	if e != nil {
		panic(e)
	}
}
