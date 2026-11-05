# Stillproof: product requirements

## Problem

A photo or document is cheap to fake and hard to check. AI image generators
make this worse every month, and "is this fake?" detectors only guess.
People who rely on photos (reporters, aid organisations, insurers, inspectors,
tenants) have no simple way to prove that a file is the one they captured, and
when they captured it.

## Product

Stillproof proves where a file came from instead of guessing whether it looks
real. The app captures a photo, fingerprints it on the phone and signs the
fingerprint with a key held on the phone. The anchoring service batches the
fingerprints it receives into a Merkle tree and records the root on Stellar.
Anyone can check the file and its receipt, with no account and no trust in us.

**It proves:** the file is unchanged since capture; it was signed by a
particular device key; and it existed no later than a specific Stellar
ledger's close time.

**It does not prove:** that the scene is genuine. A photo of a screen
verifies. We state this everywhere a verdict is shown.

## Users

| User | Job |
|---|---|
| Reporter or citizen journalist | Show an editor or the public that a photo is unedited, and when it was taken |
| NGO field officer | Prove to donors that aid was delivered |
| Claimant or adjuster | Submit damage photos that can't be swapped later |
| Tenant or landlord | Record a property's condition at move-in |
| Anyone receiving a file | Check it in a browser in seconds |

## Principles

1. Verification is deterministic and anyone can run it. No AI, and no trust in
   Stillproof's servers: the receipt and the public ledger are enough.
2. Files stay on the device. Only fingerprints leave it, and only roots go on
   chain.
3. Chain cost doesn't grow with usage: one transaction per batch, whatever the
   number of captures.
4. Be honest about limits, both in the product and in the docs.
5. Interoperate with C2PA rather than invent a rival format (milestone 3).

## Repositories

| Repository | Contents |
|---|---|
| `stillproof` (Go) | The protocol spec and test vectors; the `claim`, `merkle` and `receipt` packages; the `stillproof verify` CLI; the browser verifier (Go compiled to WebAssembly) |
| `stillproof-anchor` (Go) | The anchoring service: API, SQLite storage, batching, Stellar submission. Imports `stillproof` as a tagged module |
| `stillproof-app` (React Native, Expo) | Capture, sign, submit, receipts, share, verify |

## MVP: milestones and definitions of done

### M1. Protocol (`stillproof`) and anchoring (`stillproof-anchor`)
- [ ] `SPEC.md` v0, with test vectors shared by both repositories.
- [ ] `claim`: build, parse, sign and verify (ECDSA P-256).
- [ ] `merkle`: RFC 6962 tree, with inclusion proofs.
- [ ] Anchoring service:
  - `POST /v1/claims` and `GET /v1/receipts/{id}`;
  - SQLite storage;
  - a batch every 5 s, anchored as a `MEMO_HASH` transaction;
  - retries keep the same root.
- [ ] `stillproof verify FILE RECEIPT`: the full check against Horizon.
- [ ] CI on Linux, macOS and Windows. A testnet run is recorded in the README.

### M2. Capture app
- [ ] Capture a photo in the app, never import one.
- [ ] Hash the file on the device, sign the claim and submit it.
- [ ] Poll for the receipt.
- [ ] A list of captures with each one's status.
- [ ] Share the file together with its receipt.
- [ ] An in-app verifier.
- [ ] A software P-256 key in secure storage, labelled `software` in every
  verdict.
- [ ] Jest tests on the shared vectors: the app and Go must produce identical
  bytes.

### M3. Hardware keys and the web verifier
- [ ] Android Keystore (StrongBox where available), with a key attestation
  chain. The verifier checks it.
- [ ] iOS Secure Enclave key, plus App Attest.
- [ ] The browser verifier on GitHub Pages: drop in a file and its receipt.
- [ ] Android build in CI.

### M4. Trust-minimised and mainnet
- [ ] An Externalize proof that the anchoring ledger was confirmed by the
  network, so no Horizon trust is needed.
- [ ] The mainnet anchoring service.
- [ ] C2PA manifest embedding.

## Out of scope for the MVP

Accounts and logins; storing files on our servers; video; detecting staged
scenes; payments.

## Risks

| Risk | Mitigation |
|---|---|
| Similar apps exist off Stellar (ProofMode, ProofSnap) | Be the open, Stellar-native, standards-based version. Use C2PA to interoperate, and lead with what only we offer (Externalize proofs) |
| Horizon history is not forever | M4: Externalize proofs from history archives |
| Software keys are weak | They're labelled as such. Hardware keys come in M3 |
| Device clock is untrusted | The verdict shows the ledger time as "existed no later than". The device time is only a claim |
