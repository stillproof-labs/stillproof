//go:build js && wasm

package main

import "github.com/stillproof-labs/stillproof/embed"

// extract reads a receipt embedded in a JPEG (SPEC.md §8.3).
var extract = embed.Extract
