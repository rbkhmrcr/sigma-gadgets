package main

import (
	"testing"
)

// these are just placeholders to remind me what testing is for when i wake up lol

func BenchmarkProve(b *testing.B) {

	// do a thing here

	b.ResetTimer()
	/*
		for i := 0; i < b.N; i++ {
			kv := vals[keys[i%len(keys)]]
			if trie.Prove(kv.k) == nil {
				b.Fatalf("nil proof for %x", kv.k)
			}
		}
	*/
}

func BenchmarkVerify(b *testing.B) {
	// do some things here too
}
