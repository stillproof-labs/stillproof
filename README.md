# Stillproof

**Prove a photo is unedited, and when it was taken.** Stillproof doesn't
guess whether a photo looks real. It proves where the file came from: the
phone signs the file's fingerprint at capture, and the fingerprint is
anchored on Stellar. Anyone can check the file and its receipt, with no
account and no trust in us.

This repository holds the protocol and the tools for checking it:

| | |
|---|---|
| [`SPEC.md`](SPEC.md) | The protocol: claims, signatures, the Merkle tree, the anchor transaction and receipts |
| [`testdata/vectors.json`](testdata/vectors.json) | Test vectors every implementation must reproduce |
| `claim`, `merkle` | Go packages for the spec |

The rest of the project:

- [`stillproof-anchor`](https://github.com/stillproof-labs/stillproof-anchor):
  the service that batches fingerprints and anchors them on Stellar.
- [`stillproof-app`](https://github.com/stillproof-labs/stillproof-app): the
  capture app, built in React Native.

Where the project is going, and what's in scope, is in
[`docs/PRD.md`](docs/PRD.md).

## What a receipt proves, and what it doesn't

A valid receipt proves three things:
- the file is unchanged since the device signed it;
- which device key signed it;
- that it existed no later than a specific Stellar ledger's close time.

It does not prove the scene is genuine: a photo of a screen verifies too.

## Development

```sh
go test ./...
go test ./claim -update   # regenerate the test vectors, only on purpose
```

## License

[Apache-2.0](LICENSE)
