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
   its source is `account`, and its memo hash is `root`.
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
