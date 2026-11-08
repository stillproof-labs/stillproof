// The Stillproof browser verifier. The checks run in Go (verify.wasm,
// internal/webverify); this file reads files and draws the result.

// CHANGE ME: the hosted anchoring service, once there is one. Until then,
// pass it as ?anchor=https://….
const DEFAULT_ANCHOR = "http://localhost:8080";
const ANCHOR = (new URLSearchParams(location.search).get("anchor") || DEFAULT_ANCHOR).replace(/\/+$/, "");

const STEPS = ["claim", "file", "signature", "tree", "anchor"];
const LEVELS = {
  software: "Software key. The key was not shown to be in hardware.",
  tee: "Hardware key (TEE), attested by Android.",
  strongbox: "Hardware key (StrongBox), attested by Android.",
  "secure-enclave": "Secure Enclave key, attested by Apple.",
};
const EXPLORER = { testnet: "https://stellar.expert/explorer/testnet/tx/", mainnet: "https://stellar.expert/explorer/public/tx/" };

const $ = (id) => document.getElementById(id);
const state = { photo: null, receipt: null, receiptName: "", run: 0 };
let engine = null;

$("anchor-url").textContent = ANCHOR;

// Externalize checks validator proofs (SPEC.md §8.2) against its built-in
// trust set for the bundle's network. It loads only when a receipt carries a
// proof; verify.wasm calls this through syscall/js and compares the report
// with the receipt. If it can't load, the promise rejects and step 5 falls
// back to Horizon, saying so.
let externalize = null;
window.stillproofValidators = async (bundle) => {
  externalize ??= import("./vendor/externalize/externalize_wasm.js").then(async (m) => {
    await m.default({ module_or_path: new URL("vendor/externalize/externalize_wasm_bg.wasm", import.meta.url) });
    // Before v0.3.0 (the first with proveAncestor) it rejects v2 bundles,
    // which must not fail a receipt.
    if (typeof m.proveAncestor !== "function") throw new Error("Externalize v0.3.0 or later is needed");
    return m;
  }).catch((e) => { externalize = null; throw e; });
  const m = await externalize;
  return m.verify(bundle); // a report, or { verified: false, error }
};

function loadEngine() {
  engine ??= (async () => {
    const go = new Go();
    const { instance } = await WebAssembly.instantiateStreaming(fetch("verify.wasm"), go.importObject);
    go.run(instance);
    if (typeof window.stillproofVerify !== "function") throw new Error("the verifier did not start");
  })();
  return engine;
}
loadEngine().catch(() => { engine = null; });

// --- Input ------------------------------------------------------------------

const isReceipt = (f) => /\.json$/i.test(f.name) || f.type === "application/json";

async function take(files) {
  files = [...files];
  const photo = files.find((f) => !isReceipt(f));
  const rec = files.find(isReceipt);
  // A new photo on its own replaces the last photo and its receipt; a
  // receipt on its own waits for, or applies to, the photo.
  if (photo && !rec && state.photo) { state.receipt = null; state.receiptName = ""; }
  if (photo) state.photo = photo;
  if (rec) { state.receipt = await rec.text(); state.receiptName = rec.name; }
  const parts = [state.photo && state.photo.name, state.receiptName].filter(Boolean);
  $("loaded").textContent = parts.length ? `Loaded · ${parts.join(" · ")}` : "";
  if (state.photo) check();
  else status("Receipt added. Now drop the photo it belongs to.");
}

const drop = $("drop");
$("files").addEventListener("change", (e) => { take(e.target.files); e.target.value = ""; });
for (const ev of ["dragenter", "dragover"]) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); });
for (const ev of ["dragleave", "drop"]) drop.addEventListener(ev, () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => { e.preventDefault(); if (e.dataTransfer.files.length) take(e.dataTransfer.files); });
// Dropping anywhere else shouldn't navigate away.
for (const ev of ["dragover", "drop"]) window.addEventListener(ev, (e) => e.preventDefault());

// --- Checking ---------------------------------------------------------------

function status(text, busy = false) {
  const s = $("status");
  s.textContent = text;
  s.classList.toggle("busy", busy);
}

async function check() {
  const run = ++state.run;
  const bytes = new Uint8Array(await state.photo.arrayBuffer());
  showPhoto(state.photo, bytes);
  showHash(hex(await crypto.subtle.digest("SHA-256", bytes)));
  $("verdicts").replaceChildren();
  $("signed").hidden = true;
  status(state.receipt ? "Checking the receipt" : "Looking for a receipt", true);
  let res;
  try {
    await loadEngine();
    res = JSON.parse(await window.stillproofVerify(bytes, state.receipt, ANCHOR));
  } catch (e) {
    if (run !== state.run) return;
    status(`The verifier couldn’t run: ${e.message || e}`);
    return;
  }
  if (run !== state.run) return;
  status("");
  render(res);
  $("verdicts").focus();
}

// --- Drawing ----------------------------------------------------------------

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
};
const kb = (n) => (n < 1e3 ? `${n} B` : n < 1e6 ? `${(n / 1e3).toFixed(1)} KB` : `${(n / 1e6).toFixed(1)} MB`);
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const pad = (n) => String(n).padStart(2, "0");
function when(iso) {
  const d = new Date(iso);
  return `${pad(d.getUTCDate())} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}, ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
}
const short = (h) => (h.length > 20 ? `${h.slice(0, 10)}…${h.slice(-8)}` : h);

let objectURL = null;
let photoEdge = "";
function showPhoto(file, bytes) {
  if (objectURL) URL.revokeObjectURL(objectURL);
  objectURL = URL.createObjectURL(new Blob([bytes], { type: file.type }));
  const img = $("photo");
  img.hidden = false;
  $("noprev").hidden = true;
  img.onerror = () => { img.hidden = true; $("noprev").hidden = false; };
  img.src = objectURL;
  img.alt = `The photo being checked, ${file.name}`;
  photoEdge = `${file.name} · ${kb(file.size)}`;
  $("photo-edge").textContent = photoEdge;
  $("result").hidden = false;
}

// The fingerprint (DESIGN.md): the first 16 bytes as 64 two-bit cells, most
// significant bits first, tones 0–3 = bg, line, muted, text.
function fingerprint(h) {
  const cells = [];
  for (let i = 0; i < 16; i++) {
    const b = parseInt(h.slice(2 * i, 2 * i + 2), 16);
    for (const shift of [6, 4, 2, 0]) cells.push(el("span", `t${(b >> shift) & 3}`));
  }
  return cells;
}

function showHash(h) {
  $("fingerprint").replaceChildren(...fingerprint(h));
  $("hex").textContent = h.match(/.{16}/g).join(" ");
  $("hex").setAttribute("aria-label", `SHA-256 ${h}`);
}

function render(res) {
  const out = $("verdicts");
  out.tabIndex = -1;
  if (res.signed_sha256) {
    const s = $("signed");
    s.replaceChildren("The receipt is embedded in this photo. Without it, the file’s SHA-256 is ", el("code", "", res.signed_sha256), ".");
    s.hidden = false;
  }
  if (res.status === "none" || res.status === "pending" || res.status === "error") {
    const box = el("div", "none");
    const [title, text] = {
      none: ["No proof found for this photo", `The anchoring service at ${ANCHOR} has no receipt for this file’s SHA-256. If you have the receipt, drop it here too. An edited, resized or re-encoded copy has a different hash and can’t match.`],
      pending: ["Not anchored yet", "The anchoring service has this photo’s claim, but its batch isn’t on the ledger yet. Try again in a minute."],
      error: ["Couldn’t look this photo up", `${res.error}. Check the anchoring service at ${ANCHOR}, or drop the receipt with the photo.`],
    }[res.status];
    box.append(el("h2", "", title), el("p", "", text));
    out.replaceChildren(box);
    return;
  }
  const ok = res.checks.find((c) => !c.failed);
  if (ok) $("photo-edge").textContent = `${photoEdge} · Ledger ${ok.ledger}`;
  const n = res.checks.length;
  out.replaceChildren(...res.checks.map((c, i) => verdict(c, i, n, res.source)));
}

function verdict(c, i, n, source) {
  const v = document.getElementById("verdict-tpl").content.firstElementChild.cloneNode(true);
  const ok = !c.failed;
  const failedAt = ok ? STEPS.length : STEPS.indexOf(c.failed);
  const from = { given: "Receipt you added", embedded: "Receipt embedded in the photo", lookup: "Receipt from the anchoring service" }[source];
  v.querySelector(".vnum").textContent = [`${from}${n > 1 ? ` · ${i + 1} of ${n}` : ""}`, c.ledger && `Ledger ${c.ledger}`, c.network].filter(Boolean).join(" · ");

  const strip = v.querySelector(".strip");
  STEPS.forEach((s, k) => {
    const st = k < failedAt ? "ok" : k === failedAt ? "fail" : "empty";
    const f = el("li", `frame ${st}`);
    f.append(el("span", "", pad(k + 1)), el("b", "", s));
    f.setAttribute("aria-label", `Step ${k + 1}, ${s}: ${{ ok: "passed", fail: "failed", empty: "not checked" }[st]}`);
    strip.append(f);
  });

  const title = v.querySelector(".vtitle");
  if (ok) {
    title.textContent = `Anchored in ledger ${c.ledger}`;
  } else {
    title.textContent = `Failed at the ${c.failed} step`;
    const r = v.querySelector(".reason");
    r.textContent = c.reason.charAt(0).toUpperCase() + c.reason.slice(1) + (/[.!?]$/.test(c.reason) ? "" : ".");
    r.hidden = false;
  }

  const dl = v.querySelector(".lines");
  const line = (label, ...value) => {
    const dd = el("dd");
    dd.append(...value);
    dl.append(el("dt", "edge", label), dd);
  };
  if (ok) {
    line("Unchanged", "Unchanged since signed by key ", code(c.key), ".");
    line("Existed by", `Existed no later than ${when(c.not_after)} (ledger ${c.ledger}).`);
  }
  if (ok) line("Captured", `${when(c.captured)}, by the device’s own clock. That time is a claim, not evidence.`);
  if (ok) {
    line("Protection", LEVELS[c.level] || c.level);
    const how = c.anchor_checked === "validators"
      ? "Proven by the Stellar validators’ signatures, checked in this browser with Externalize."
      : "Read from Horizon, a Stellar API server this page trusts for it.";
    line("Anchor checked", el("span", `how ${c.anchor_checked}`, c.anchor_checked), ` ${how}`);
  }
  if (c.tx) {
    const a = el("a", "mono", short(c.tx));
    a.href = (EXPLORER[c.network] || EXPLORER.testnet) + c.tx;
    a.title = c.tx;
    a.setAttribute("aria-label", `Transaction ${c.tx} on stellar.expert`);
    line("Transaction", a);
  }
  if (c.anchor_note) {
    // Why the validator proof wasn't checked; step 5 then used Horizon.
    const nt = v.querySelector(".vnote");
    const n = c.anchor_note.charAt(0).toUpperCase() + c.anchor_note.slice(1);
    nt.textContent = `${n}${/[.!?]$/.test(n) ? "" : "."} The anchor was read from Horizon instead.`;
    nt.hidden = false;
  }
  if (ok) v.querySelector(".caveat").textContent = c.caveat;
  else v.querySelector(".caveat").remove();
  return v;
}

function code(text) {
  const e = el("code", "", short(text));
  e.title = text;
  e.setAttribute("aria-label", text);
  return e;
}
