//go:build js && wasm

// Command wasm is the browser verifier's engine. It defines
//
//	stillproofVerify(fileBytes: Uint8Array, receiptJSON: string|null, anchorURL: string): Promise<string>
//
// resolving to the JSON of a webverify.Result. If the page defines
// stillproofValidators(bundleJSON: string): Promise<report>, resolving to
// Externalize's verification report, it is used to check validator proofs
// (SPEC.md §8.2). A rejection there means the proof couldn't be checked.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"syscall/js"
	"time"

	"github.com/stillproof-labs/stillproof/internal/webverify"
)

func main() {
	js.Global().Set("stillproofVerify", js.FuncOf(verify))
	select {}
}

func verify(_ js.Value, args []js.Value) any {
	if len(args) < 3 {
		return reject(errors.New("stillproofVerify(fileBytes, receiptJSON, anchorURL)"))
	}
	file := make([]byte, args[0].Get("length").Int())
	js.CopyBytesToGo(file, args[0])
	var rec []byte
	if t := args[1].Type(); t == js.TypeString {
		rec = []byte(args[1].String())
	}
	o := webverify.Options{
		Anchor:     args[2].String(),
		Extract:    extract,
		Validators: validators(),
	}
	return promise(func() (any, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		b, err := json.Marshal(webverify.Verify(ctx, file, rec, o))
		return string(b), err
	})
}

// validators bridges to the page's Externalize check, if it has one.
func validators() func(context.Context, []byte) ([]byte, error) {
	f := js.Global().Get("stillproofValidators")
	if f.Type() != js.TypeFunction {
		return nil
	}
	return func(ctx context.Context, bundle []byte) ([]byte, error) {
		v, err := await(ctx, f.Invoke(string(bundle)))
		if err != nil {
			return nil, err
		}
		return []byte(js.Global().Get("JSON").Call("stringify", v).String()), nil
	}
}

// promise runs f off the event loop, so its network calls can complete.
func promise(f func() (any, error)) any {
	var handler js.Func
	handler = js.FuncOf(func(_ js.Value, args []js.Value) any {
		resolve, rejectFn := args[0], args[1]
		go func() {
			defer handler.Release()
			v, err := f()
			if err != nil {
				rejectFn.Invoke(js.Global().Get("Error").New(err.Error()))
				return
			}
			resolve.Invoke(v)
		}()
		return nil
	})
	return js.Global().Get("Promise").New(handler)
}

func reject(err error) any {
	return promise(func() (any, error) { return nil, err })
}

// await waits for a JS promise.
func await(ctx context.Context, p js.Value) (js.Value, error) {
	type result struct {
		v   js.Value
		err error
	}
	ch := make(chan result, 1)
	ok := js.FuncOf(func(_ js.Value, a []js.Value) any { ch <- result{v: a[0]}; return nil })
	bad := js.FuncOf(func(_ js.Value, a []js.Value) any {
		ch <- result{err: errors.New(js.Global().Get("String").Invoke(a[0]).String())}
		return nil
	})
	js.Global().Get("Promise").Call("resolve", p).Call("then", ok, bad)
	select {
	case r := <-ch:
		ok.Release()
		bad.Release()
		return r.v, r.err
	case <-ctx.Done():
		return js.Value{}, ctx.Err() // ok and bad stay alive for the late settle
	}
}
