package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	secp "github.com/btcsuite/btcd/btcec"
	poly "github.com/jongukim/polynomial"
	"golang.org/x/crypto/sha3"
	"io/ioutil"
	//	"math"
	"math/big"
	"strconv"
)

// Group is secp256k1 as defined in btcec
var Group = secp.S256()
var grouporder = Group.N

// H is an EC point with unknown DL
var H, _ = HashToCurve([]byte("i am a stupid moron"))

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
	pubkeys := ConvertPubKeys(pk)
	privkey := big.NewInt(0)
	// ive just picked the 3rd (2nd counting from 0th) privkey here :)
	// why not just read it from the file ?????
	privkey.SetString("23246495091784532220524749001303194962250020895499760086019834032589186452479", 10)
	proofa, proofb, proofc := Prover(pubkeys, 3, 2, privkey)
	fmt.Println("proofa : ", proofa)
	fmt.Println("proofb : ", proofb)
	fmt.Println("proofc : ", proofc)

	pv := Verify(pubkeys, 3, proofa, proofb, proofc)
	fmt.Println("verificaaaationnnnnnn : ", pv)
}

/* now we unwrap all the private keys
	for i := 0; i < len(sk.Keys); i++ {
		privbytes, err := hex.DecodeString(sk.Keys[i])
		if err != nil {
			panic(err)
		}
		privbn := new(big.Int).SetBytes(privbytes)
	}

	// len(sk.Keys) is a silly hacky way of getting the ring size.
	// it should defs be changed irl
	var polyarray []poly.Poly
	for i := 0; i < len(sk.Keys); i++ {
		randompoly := PolynomialBuilder(int(3), len(sk.Keys), int(i))
		// we build polyarray like p[0][k], p[1][k], ...
		polyarray = append(polyarray, randompoly)
	}
	fmt.Println(polyarray)

}


func Mint() CurvePoint, *big.Int, *big.Int {
	privkey, e := rand.Int(rand.Reader, grouporder)
	check(e)
	serial, e := rand.Int(rand.Reader, grouporder)
	check(e)
	c := commit(serial, privkey)
	return c, privkey, serial
}

func Spend(pp, M, c, C) *big.Int {
}

func SpendVerify(pp, M, serial, C, pi) {
}

*/

// Prover is the gk prover routine. it's needed in ring signatures and stuff.
// if Ring has a length (?) then we don't need to submit the length separately :)
func Prover(ring Ring, ringlength int, signerindex int, privatekey *big.Int) ([]CurvePoint, []*big.Int, *big.Int) {

	/* -----------------------------------------
	this is the first part of the sigma protocol
	----------------------------------------- */

	ringbin := strconv.FormatInt(int64(ringlength), 2)
	// TODO: check if the bitlength = n is correct!!
	n := uint(len(ringbin) + 1)
	randomvars := make([]*big.Int, 0)
	commitments := make([]CurvePoint, 0)
	// j is the bitwise index, always :) in the paper it's 1, ..., n, but we'll count from 0.
	for j := uint(0); j < n; j++ {
		// we could use a for loop here with i from 0 to 4 ?
		rj, e := rand.Int(rand.Reader, grouporder)
		Check(e)
		randomvars = append(randomvars, rj)
		// so r[j] will be randomvars[5*j]
		aj, e := rand.Int(rand.Reader, grouporder)
		Check(e)
		randomvars = append(randomvars, aj)
		// so a[j] will be randomvars[5*j + 1]
		sj, e := rand.Int(rand.Reader, grouporder)
		Check(e)
		randomvars = append(randomvars, sj)
		// so s[j] will be randomvars[5*j + 2]
		tj, e := rand.Int(rand.Reader, grouporder)
		Check(e)
		randomvars = append(randomvars, tj)
		// so t[j] will be randomvars[5*j + 3]
		rhok, e := rand.Int(rand.Reader, grouporder)
		Check(e)
		randomvars = append(randomvars, rhok)
		// so rho[k] will be randomvars[5*j + 4]
		// should these actually not just use the variables aj, sj, etc, as they are still
		// set to the ones that are needed? is this lots of unnecessary array fetching?

		// clj = lj * g + rj * h
		bigintbit := big.NewInt(int64(((signerindex >> j) & 0x1)))
		newcommitment := Commit(bigintbit, randomvars[5*j])
		commitments = append(commitments, newcommitment)
		// clj will be commitments[3*j]

		// caj = aj * g + sj * h
		commitments = append(commitments, Commit(randomvars[5*j+1], randomvars[5*j+2]))
		// caj will be commitments[3*j + 1]

		// cbj = (lj * aj) * g + tj * h
		z := new(big.Int)
		commitments = append(commitments, Commit(z.Add(bigintbit, randomvars[5*j+1]), randomvars[5*j+3]))

		// cdk = (for i = 0, ..., N-1) p[i][k] * ci    +      0 * g + rhok * h
		// product temp is p[i][k] * c[i]
		var producttemp CurvePoint
		for i := 0; i < ringlength; i++ {
			// polytemp is p[i][k]
			polytemp := PolynomialBuilder(signerindex, ringlength, i)
			// cdk lhs is p[i][k] * c[i] for a given i
			fmt.Println("signerindex : ", signerindex)
			fmt.Println("i : ", i)
			fmt.Println("j : ", j)
			fmt.Println("poly : ", polytemp)
			cdklhs := (ring.PubKeys[i]).ScalarMult(polytemp[j])

			if i == 0 {
				// each type we loop through the k and start on a new i we reset the product
				producttemp = ring.PubKeys[i].ScalarMult(polytemp[j])
			} else {
				// we're using EC points so multiplication is really addition
				// this is adding the latest p[i][k] * c[i] to the previous ones (for given k)
				z := producttemp.Add(cdklhs)
				producttemp = z
			}
		}
		// cdk = above product + 0 * g + rho * h
		newcommitment = Commit(big.NewInt(0), randomvars[5*j+4])
		commitments = append(commitments, newcommitment.Add(producttemp))

	}

	/* ------------------------------------
	this is where we generate the challenge
	------------------------------------ */

	// should we just carry on the loop above? who cares
	// we need to convert the challenge into a big int :(
	array := sha3.Sum256([]byte("lots of cool stuff including the commitments"))
	challenge := Convert(array[:])

	/* ------------------------------------------
	this is the second part of the sigma protocol
	------------------------------------------ */

	var responses []*big.Int
	for j := uint(0); j < n; j++ {

		z := new(big.Int)
		// fj = lj * x + aj
		lj := big.NewInt(int64(((signerindex >> j) & 0x1)))
		fj := z.Mul(lj, challenge)
		fj = z.Mod(fj, grouporder)
		fj = z.Add(fj, randomvars[5*j+1])
		fj = z.Mod(fj, grouporder)
		// so fj = responses[3*j]
		responses = append(responses, fj)

		// zaj = rj * x + sj
		// TODO: is using z like this weird??
		z = new(big.Int)
		zaj := z.Mul(randomvars[5*j], challenge)
		zaj = z.Mod(zaj, grouporder)
		zaj = z.Add(zaj, randomvars[5*j+2])
		zaj = z.Mod(zaj, grouporder)
		// so zaj = responses[3*j + 1]
		responses = append(responses, zaj)

		// zbj = rj * (x - fj) + tj
		z = new(big.Int)
		zbj := z.Sub(challenge, fj)
		zbj = z.Mod(zbj, grouporder)
		zbj = z.Mul(randomvars[5*j], zbj)
		zbj = z.Mod(zbj, grouporder)
		zbj = z.Add(zbj, randomvars[5*j+3])
		zbj = z.Mod(zbj, grouporder)
		// so zbj = responses[3*j + 2]
		responses = append(responses, zbj)

	}

	// zd = r * x ** n - sum from k = 0 to k = n - 1 of rhok * x ** k
	z := new(big.Int)
	ztemp := new(big.Int)
	zdsum := new(big.Int)

	// zd (lhs) = r * x ** n
	rxn := z.Exp(challenge, big.NewInt(int64(n)), grouporder)
	rxn = z.Mod(rxn, grouporder)
	rxn = z.Mul(rxn, privatekey)
	rxn = z.Mod(rxn, grouporder)

	for k := uint(0); k < n; k++ {
		z := new(big.Int)
		// x ** k
		xk := z.Exp(challenge, big.NewInt(int64(k)), grouporder)
		// zd = SUM( rhok * x ** k )
		zdelement := z.Mul(randomvars[5*k+4], xk)
		zdelement = z.Mod(zdelement, grouporder)
		// zd = sum over k of the above
		zdsum = z.Add(zdsum, zdelement)
		zdsum = z.Mod(zdsum, grouporder)
		ztemp = zdsum
	}

	zd := z.Sub(rxn, ztemp)
	zd = z.Mod(zd, grouporder)

	return commitments, responses, zd
}

// Verify is the gk **proof** verification. (contrast with SpendVerify)
func Verify(ring Ring, ringlength int, commitments []CurvePoint, responses []*big.Int, zd *big.Int) bool {
	for i := 0; i < len(commitments); i++ {
		check := Group.IsOnCurve(commitments[i].X, commitments[i].Y)
		if check == false {
			return false
		}
	}

	array := sha3.Sum256([]byte("lots of cool stuff including the commitments"))
	challenge := Convert(array[:])
	fmt.Println(challenge)
	ringbin := strconv.FormatInt(int64(ringlength), 2)
	// TODO: check if the bitlength = n is correct!!
	n := int(len(ringbin) + 1)

	for j := 0; j < n; j++ {
		// (x * clj) + caj == commit(fj, zaj)
		// (challenge * commitments[4*j]) + commitments[4*j + 1] == commit(responses[3*j], responses[3*j+1])
		xc := (commitments[4*j]).ScalarMult(challenge)
		fmt.Println("XC : ", xc)
		lhs := xc.Add(commitments[4*j+1])
		fmt.Println("LHS : ", lhs)
		rhs := Commit(responses[3*j], responses[3*j+1])
		fmt.Println("RHS : ", rhs)
		if rhs.X == lhs.X {
			fmt.Println("this actually makes verification true......")
			return false
		}

	}
	fmt.Println("you don't wanna be here")
	return true
}

// Commit forms & returns a pedersen commitment with the two arguments given
func Commit(a *big.Int, b *big.Int) CurvePoint {
	ga := CurvePoint{}.ScalarBaseMult(a)
	hb := H.ScalarMult(b)
	return hb.Add(ga)
}

// HashToCurve takes a byteslice and returns a CurvePoint (whose DL remains unknown!)
func HashToCurve(s []byte) (CurvePoint, error) {
	q := Group.P
	x := big.NewInt(0)
	y := big.NewInt(0)
	z := big.NewInt(0)
	// what is this magical number
	z.SetString("57896044618658097711785492504343953926634992332820282019728792003954417335832", 10)

	// sum256 outputs an array of 32 bytes :) => are we menna use   keccak? does this work?
	array := sha3.Sum256(s)
	x = Convert(array[:])
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

// PolynomialBuilder builds the weird polynomials we need in the GK proving algo
func PolynomialBuilder(signerindex int, ringsize int, currenti int) poly.Poly {

	// this is just to print and get the bit length, n
	// TODO: print this and see if its right
	// signerindexbin := strconv.FormatInt(int64(signerindex), 2)
	ringbin := strconv.FormatInt(int64(ringsize), 2)
	// the product should be of length = bitlength(ringsize)
	var product poly.Poly
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
		Check(e)
		z, e := rand.Int(rand.Reader, grouporder)
		Check(e)

		// we compare i (the current index) to l (the signer index), bitwise
		if (currenti >> j & 0x1) == 0 {
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

		if (currenti >> j & 0x1) == 1 {
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
			// is there a way to make sure the polynomials are always a certain length
			// even is lots of entries are 0? :/
			product = poly.NewPolyInts(0)
			product = functiontemp
		} else {
			product = product.Mul(functiontemp, grouporder)
			product = append(product, big.NewInt(0))
			product = append(product, big.NewInt(0))
			product = append(product, big.NewInt(0))
			product = append(product, big.NewInt(0))
		}
	}
	return product
}

// ConvertPubKeys takes the string rep of coords ('x', 'y') and changes to *big.Ints
func ConvertPubKeys(rn RingStr) Ring {

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

// Convert goes byte slice -> *big.Int
func Convert(data []byte) *big.Int {
	z := new(big.Int)
	z.SetBytes(data)
	return z
}

// Check just does rly trivial error handling
func Check(e error) {
	if e != nil {
		panic(e)
	}
}
