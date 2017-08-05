package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha3" // we need a hash function that isn't vuln to length extension attacks
	"encoding/hex"
	"errors"
	"fmt"
	secp "github.com/btcsuite/btcec"
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
