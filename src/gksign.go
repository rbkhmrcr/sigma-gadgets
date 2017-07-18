package main

import (
  secp "btcec"
  "crypto/rand"
  "crypto/sha3"
  "bytes"
  "fmt"
  "math/big"
)

var Group *secp.KoblitzCurve


