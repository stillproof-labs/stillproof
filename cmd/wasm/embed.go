//go:build js && wasm

package main

import "github.com/stillproof-labs/stillproof/receipt"

// extract reads a receipt embedded in a JPEG (SPEC.md §8.3).
//
// Seam: nil until package embed lands, then
//
//	var extract = embed.Extract
var extract func(jpeg []byte) (receipt.Receipt, []byte, error)
