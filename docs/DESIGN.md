# Stillproof design: the darkroom ledger

Stillproof is evidence, so it should look like a darkroom and an archive, not
like a fintech dashboard. Warm blacks, fibre-paper whites, one safelight
colour, and data set like the edge print on a strip of film. The app and the
web verifier share everything below.

## Type

| Role | Font | Use |
|---|---|---|
| Display | **Gloock** | Screen titles, the verdict, big numbers. Never below 22 px |
| Text | **Schibsted Grotesk** (400, 500, 700) | Everything people read |
| Data | **Fragment Mono** | Hashes, times, ledgers, keys, and edge labels |

Edge labels are the signature detail: Fragment Mono, 11 px, uppercase,
letter-spacing 0.12em, muted colour, as in
`FRAME 014 · 05 NOV 2026 04:08:12 UTC · LEDGER 5565275`.

App: `@expo-google-fonts/gloock`, `schibsted-grotesk`, `fragment-mono`.
Web: the same three from Google Fonts.

## Colour

Dark ("darkroom") is the default. Light ("print") follows the system setting.

| Token | Darkroom | Print | Use |
|---|---|---|---|
| `bg` | `#0F0E0C` | `#F3EEE3` | Background: tray black, fibre paper |
| `surface` | `#191714` | `#EAE3D4` | Raised areas |
| `line` | `#2E2A25` | `#D2C9B6` | Hairlines, 1 px |
| `muted` | `#8E877B` | `#6F685C` | Edge labels, secondary text |
| `text` | `#EDE6D6` | `#15130F` | Primary text |
| `safelight` | `#F2A33A` | `#B8651A` | The one accent: capture, primary action, live state |
| `ok` | `#9FDCA0` | `#2F7A45` | Verified |
| `fail` | `#F0563F` | `#B83A26` | Failed |

Safelight is rare: at most one safelight element on a screen. Never use
gradients or shadows.

## Shape and space

- Corners: 2 px. Hairline rules instead of cards with shadows.
- Space: 4, 8, 12, 16, 24, 32, 48.
- Photos are framed like prints: a 1 px `line` border, with an edge label
  under each one.

## Signature elements

1. **Fingerprint.** Every SHA-256 is also drawn as an 8 × 8 grid. The first
   16 bytes give 64 two-bit cells, most significant bits first, tones 0–3 =
   `bg`, `line`, `muted`, `text`. Cells are square with a 1 px gap. Two
   files match if their fingerprints match at a glance. The grid sits beside
   the hex, never replaces it.
2. **Contact sheet.** The capture list is a three-column grid of square
   thumbnails. Each one has a frame number (`014`) and a 6 px status dot:
   `safelight` pending, `ok` anchored, `fail` failed.
3. **Proof strip.** A verdict is a strip of five frames, one per step of
   SPEC §6 (claim, file, signature, tree, anchor). A passed frame is filled
   `ok`. The failed frame is filled `fail` and named. Frames after it are
   empty outlines. Below the strip are the verdict lines, the protection
   level, how the anchor was checked, and the caveat in Gloock.
4. **Shutter.** The capture button is a 72 px ring in `safelight`, with a
   2 px gap and a solid inner disc. It is the only round element.

## Voice

Short, plain and exact. Say "Anchored in ledger 5565275", not "Success!". A
failure names the step and the reason. Never claim more than the caveat
allows.
