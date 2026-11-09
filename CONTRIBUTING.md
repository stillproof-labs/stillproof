# Contributing

This repository holds the Stillproof protocol (`SPEC.md`), its test vectors,
the Go packages that verify receipts, the `stillproof` CLI and the browser
verifier. It takes part in the
[Stellar Wave](https://www.drips.network/wave/stellar) program; Wave issues are
labeled with their complexity. The ground rules for every Stillproof Labs
repository are in the
[organization guide](https://github.com/stillproof-labs/.github/blob/main/CONTRIBUTING.md):
get assigned first, one issue per PR, and the spec comes first.

## Setup

```sh
git clone https://github.com/stillproof-labs/stillproof && cd stillproof
go test ./...
```

Go 1.25 or later (`go.mod` pins it). The default tests run offline: Horizon
and the Externalize CLI are replaced by fakes, and the tests that need the real
`externalize` CLI or c2patool skip without them.

To try the browser verifier:

```sh
scripts/build-web.sh && python3 -m http.server -d web
# http://localhost:8000/?anchor=<anchoring service URL>
```

## Before you open a PR

These are the checks CI runs (`.github/workflows/ci.yml`):

```sh
gofmt -l .                       # must print nothing
go vet ./...
go test -race -count=1 ./...
GOOS=js GOARCH=wasm go vet ./cmd/wasm
GOOS=js GOARCH=wasm go build -o /dev/null ./cmd/wasm
golangci-lint run
```

CI also runs the tests on Linux, macOS and Windows, govulncheck, and two
interop jobs you can run locally if you have the tools:

- **c2patool:** `C2PATOOL=/path/to/c2patool go test -count=1 -run TestC2patool -v ./embed`.
  CI pins c2patool 0.27.22.
- **Externalize:** with `externalize` v0.3.0 or later on `PATH`,
  `NEED_EXTERNALIZE=1 go test -count=1 -v -run 'Externalize|Real|ResultSet' ./receipt/`.

A change to `embed` should pass the c2patool job. A change to `receipt`'s proof
checking should pass the Externalize job.

## Vectors and fixtures

- **`testdata/vectors.json`** is the protocol's test vectors. The app
  (stillproof-app) keeps a copy, and both implementations must reproduce it
  byte for byte. Regenerate it only on purpose, with `go test ./claim -update`,
  and only together with a SPEC.md change. Signatures are randomised, so
  regenerating rewrites them all. Say in the PR that the app's copy needs
  updating.
- **`testdata/testnet-*`, `testdata/bundle-testnet-5565106.json`:** a real
  photo, receipt and Externalize bundle from a testnet run. Don't edit them; a
  test that needs a variant builds it in code.
- **`attest/testdata/`:** real Android attestation chains and an App Attest
  object from devices. They are only valid at the times the tests pass in, and
  they can't be regenerated without the device, so never edit or replace them.
  New cases use the synthetic chain helpers in `attest/*_test.go`.
- **`web/vendor/externalize/`** is fetched by `scripts/vendor-externalize.sh`
  and is not committed, apart from `NOTICE`.

## Web verifier changes

`web/` follows [docs/DESIGN.md](docs/DESIGN.md). Include screenshots in both
themes, and at 360 px wide, in the PR. Verdict text keeps to the caveat: a
receipt proves the file is unchanged and when it existed, not that the scene is
genuine.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org): `feat(embed): …`,
`fix(receipt): …`, `docs: …`, `test: …`.
