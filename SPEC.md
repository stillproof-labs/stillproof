# Stillproof protocol, v0

Test vectors live in [`testdata/vectors.json`](testdata/vectors.json).
Implementations must reproduce them byte for byte.

## 1. Claim

A claim is UTF-8 text: these five lines, in this order, each ending in `\n`:

```text
stillproof/claim/v0
sha256 <hex>
type <media type>
captured <unix ms>
key <hex>
```

| Field | Format |
|---|---|
| `sha256` | SHA-256 of the file's exact bytes, as 64 lowercase hex characters |
| `type` | Media type, lowercase, such as `image/jpeg` |
| `captured` | Capture time on the device clock: milliseconds since the Unix epoch, in decimal, with no leading zeros |
| `key` | The device's P-256 public key, SEC1 uncompressed (`04‖X‖Y`), as 130 lowercase hex characters |

The device clock is a claim, not evidence. See §5.

## 2. Signature

The device signs SHA-256(claim) with ECDSA P-256. The signature is `r‖s`,
each 32 bytes big-endian, as 128 lowercase hex characters. `s` must be in
the lower half of the curve order, which makes each signature canonical.
Verifiers reject a high `s`.

A **signed claim** is the claim followed by one more line:

```text
sig <hex>
```

## 3. Leaves and the tree

- **Leaf hash:** `SHA-256(0x00 ‖ signed claim)`. Its hex form is the claim's
  **id**.
- **Tree:** the Merkle tree hash of RFC 6962 §2.1, with nodes
  `SHA-256(0x01 ‖ left ‖ right)`.
- **Inclusion proofs:** the audit paths of RFC 6962 §2.1.1, verified as in
  RFC 9162 §2.1.3.2.

Leaves are ordered as the anchoring service received them. An audit path
alone doesn't fix the tree size (RFC 9162 allows a path to verify for more
than one size); what binds a leaf is the root, which is anchored on chain.

## 4. Anchor transaction

An anchoring service records one tree root per batch, as a Stellar
transaction with:

- **source:** the service's anchor account;
- **memo:** `MEMO_HASH` set to the root;
- **operations:** exactly one, `bump_sequence` with `bump_to` 0. This
  changes nothing and costs the minimum fee.

The transaction must be successful. Who runs the anchor account doesn't
matter for timing: a ledger can't be backdated, so a root in ledger L proves
every leaf existed by L's close time. A dishonest operator can only refuse or
delay anchoring.

## 5. Receipt

```json
{
  "v": 0,
  "claim": "<signed claim>",
  "index": 3,
  "size": 8,
  "proof": ["<hex>", "…"],
  "root": "<hex>",
  "anchor": {
    "network": "testnet",
    "account": "G…",
    "tx": "<hex>",
    "ledger": 123,
    "closed_at": "2026-11-05T12:00:00Z"
  }
}
```

`network` is `testnet` or `mainnet`. `ledger` and `closed_at` are a convenience. Verifiers read both from the
network and fail if they differ.

## 6. Verifying a file against a receipt

1. **The claim:** the receipt's `claim` parses as a signed claim, with
   exactly the lines above.
2. **The file:** SHA-256 of the file equals `sha256`.
3. **The signature:** `sig` is a valid low-`s` signature by `key` over
   SHA-256 of the claim lines.
4. **The tree:** the leaf hash, `index`, `size` and `proof` recompute `root`.
5. **The anchor:** on `network`, transaction `tx` exists and was successful,
   its source is `account`, and its memo hash is `root`. With a v1
   `anchor.proof`, this is checked against the validators' signatures
   instead (§8.2).
6. **The verdict:** report all of the following.
   - "Unchanged since signed by key `key`."
   - "Existed no later than `closed_at` (ledger `ledger`)."
   - The device-claimed capture time.
   - The key's protection level: `software` in v0; hardware and attested
     levels arrive with claim v1.
   - Always, word for word: "This proves the file is unchanged and when it
     existed. It does not prove the scene is genuine."

If any check fails, the verdict names the first step that failed.

## 7. Anchoring service API

| Route | Request | Response |
|---|---|---|
| `POST /v1/claims` | A signed claim (`text/plain`) | `202 {"id": "<hex>"}`. `400` if malformed or the signature is invalid |
| `GET /v1/receipts/{id}` | | `200` with the receipt once anchored, `202 {"status": "pending"}` before then, `404` if unknown |
| `GET /healthz` | | `200` |

Submitting the same signed claim twice returns the same id and leaf.

## 8. Additions in receipt v1

A v1 receipt is a v0 receipt with `"v": 1` and any of the optional fields
below. Verifiers accept `v` 0 and 1. Fields not listed here are an error.

### 8.1 Key attestation

`attestation` shows that the claim's key is held in hardware. It is per key,
not per claim: a device registers it once (§8.4), and the anchoring service
copies it into every receipt for that key.

```json
"attestation": { "kind": "android-key", "chain": ["<base64 DER>", "…"] }
"attestation": { "kind": "apple-app-attest", "key_id": "<base64>", "object": "<base64 CBOR>" }
```

- **`android-key`:** an Android Keystore attestation chain, leaf first. It
  must verify up to a Google hardware attestation root. The leaf's public key
  must equal `key`, and its key description (OID 1.3.6.1.4.1.11129.2.1.17)
  must have challenge `stillproof/key/v1`, purpose sign, and
  `attestationSecurityLevel` 1 (level `tee`) or 2 (level `strongbox`).
  Security level 0 is rejected.
- **`apple-app-attest`:** an App Attest attestation object, verified as Apple
  documents it, with `clientDataHash` = SHA-256 of the 65 key bytes. That
  binds the claim key (a Secure Enclave key) to a genuine instance of the app.
  Level `secure-enclave`.

A receipt without `attestation` has level `software`. A failed attestation
fails the **signature** step: a receipt never quietly drops to `software`.

### 8.2 Validator proof of the anchor

`anchor.proof` is an [Externalize](https://github.com/Externalize-Labs/externalize)
bundle (`externalize/bundle/v1`) for ledger `ledger` that claims
`{"kind": "transaction", "tx_hash": tx}` and includes the ledger's
transaction set (`transactions`). With a proof, step 5 is checked against the
validators' signatures instead of Horizon. The verdict says which way step 5
was checked: `anchor_checked` is `validators` or `horizon`.

What the bundle proves, and how:

- **Ledger and close time.** `externalize verify --json` exits 0 only if
  validators satisfying its trust set (the built-in set for the bundle's
  network unless `--trust` is given) signed `EXTERNALIZE` for slot `ledger`
  with exactly the header's `StellarValue`. That value holds the close time
  and the transaction set's hash. The report's `ledger.sequence` and
  `ledger.close_time` must equal `ledger` and `closed_at`. The bundle's
  `network` must be the passphrase of `network`.
- **Inclusion.** The CLI checks `transactions` against the signed transaction
  set hash and that `tx` is in it. A transaction in the set was applied in
  that ledger.
- **Source and memo.** The CLI doesn't report them. The verifier finds, in
  `transactions`, the bytes whose hash is `tx`: SHA-256 of the network ID,
  `ENVELOPE_TYPE_TX` and the transaction's XDR. Only that transaction hashes
  to `tx`, so its source must be `account` and its memo `MEMO_HASH` `root`.
  Only a plain v1 envelope with an Ed25519 source is accepted; a fee-bump
  anchor fails.
- **Success is not proven by the signatures.** The CLI reads it from the
  result set, which only the header's `txSetResultHash` commits to, and the
  validators don't sign the header. Anyone can rewrite the result set,
  recompute `txSetResultHash` and the header hash, and the bundle still
  verifies. The verifier still requires the claim to say `succeeded`, but it
  doesn't depend on it: the memo is in the agreed transaction set either way.
- **A bundle without `transactions` proves nothing about the transaction**
  (its inclusion rests on the result set alone), so it fails step 5.

Nothing in step 5 comes from Horizon when the proof is checked. What is
trusted instead is the verifier's trust set; the CLI's built-in testnet set
is SDF's three validators, any 2 of 3.

A proof that is rejected, or doesn't match, fails step 5: Horizon can't
overrule it. A verifier that can't check proofs (no `externalize` installed,
or it can't run) checks all of step 5 through Horizon, says `horizon`, and
says why in `anchor_note`. It never reports `validators` without checking.

The anchoring service adds the proof, and sets `v` to 1, once the anchor's
ledger is in a history archive, a few minutes after it closes. Until then
the receipt has no proof.

### 8.3 Embedded receipts

A JPEG can carry its own receipt, as a C2PA manifest store in APP11
segments. The manifest's assertion `org.stillproof.receipt` holds the receipt
JSON. Embedding only inserts segments, so removing every C2PA APP11 segment
gives back the exact bytes that were signed. A verifier given a photo with no
separate receipt extracts the receipt, strips the segments and runs §6 on the
result.

Pinned details: one manifest with a v2 claim (`c2pa.claim.v2`) and the
assertions `c2pa.actions.v2` (`c2pa.created`), `c2pa.hash.data` (one
exclusion covering the APP11 segments) and `org.stillproof.receipt` (a JSON
assertion). The APP11 segments go right after the leading APP0 and APP1
segments, or after SOI if there are none, so Exif stays first.

The C2PA signer is whoever embedded the receipt, usually with a self-signed
certificate. C2PA tools show that signer as untrusted. That is expected: the
proof is the receipt, not the C2PA signature.

### 8.4 API additions

| Route | Request | Response |
|---|---|---|
| `POST /v1/keys` | `{"key": "<hex>", "attestation": {…}}` | `204`. `400` if the attestation doesn't verify for that key |
| `GET /v1/receipts?sha256=<hex>` | | `200 {"receipts": […]}`: every anchored receipt for a file with that hash, oldest first. `202 {"status": "pending"}` if all are pending. `404` if unknown |

The lookup lets anyone check a photo with nothing but the photo.
