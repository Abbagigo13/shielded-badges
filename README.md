# ShieldedBadges

Prove a fact about a credential without revealing who you are or the exact number behind it.

Entry for ZECATHON, **Core & Tooling** track.
Live demo: <https://shielded-badges.vercel.app/>

A holder proves: *"I hold a credential from this issuer, and its value is at least N."*
The verifier learns that single fact. It does not learn the holder's secret, the credential
value, or which credential in the issuer's tree belongs to the holder.

The proof is a zero-knowledge proof made with Halo2 (Rust, compiled to WebAssembly). It is
generated and verified entirely inside the browser.

---

## What is real and what is a mock

| Real (built and tested) | Simulated (demo shortcuts) |
| --- | --- |
| A Halo2 circuit written in Rust | The issuer is simulated. The other 15 credentials in its tree are fake. |
| Proof generation and verification in the browser, in a Web Worker | The issuer does not sign its Merkle root. The demo verifier simply takes the root it is given. |
| Poseidon hashing, Merkle membership (4 levels), a 64-bit range check, and a scoped nullifier | The demo issuer is handed the holder's secret to build the tree leaf. A real issuer would receive only `Poseidon(secret)`. |
| Rejection of replayed, inflated, wrong-threshold and tampered proofs (see Tests) | Prover and verifier run in the same page. |
| Double-claim blocking through a nullifier registry | The nullifier registry lives in browser memory only. |
| A typed TypeScript SDK (`packages/core`) | No wallet, keys or shielded data are used. One optional button reads the public Zcash block height (see below). |

---

## What the proof says

One circuit proves five things at once.

| # | Statement | How |
| --- | --- | --- |
| 1 | I know a secret | `id = Poseidon(secret)` |
| 2 | The credential is bound to me, the badge and the value | `leaf = Poseidon(id, badge_type, value)` |
| 3 | The credential is in the issuer's tree | Merkle path of depth 4 up to the public `root` |
| 4 | The value is at least the threshold | `value - threshold` is split into 64 bits, each bit is 0 or 1, and the bits add back up to the difference |
| 5 | Here is my nullifier for this scope | `nullifier = Poseidon(secret, badge_type, scope)` |

The value used in statement 4 is forced to be the same value that is hashed into the leaf in
statement 2, so a holder cannot claim a bigger value than the issuer issued.

**Public inputs:** `root`, `badge_type`, `threshold`, `scope`, `nullifier`.
**Private inputs:** `secret`, `value`, the Merkle siblings, and the left/right path bits.

---

## Privacy properties

- The verifier receives a proof, the root, the badge type, the threshold, the scope and the nullifier.
- The verifier cannot see the secret, the credential value, or which leaf is the holder's.
- The nullifier includes the scope. The same holder gets a **different, unlinkable** nullifier in
  every scope, so two verifiers cannot tell they saw the same person.
- Inside one scope the nullifier is the same every time. That is deliberate: it is how a
  verifier blocks a double claim.
- The anonymity set is the number of credentials in the issuer's tree: 16 in this demo.
- The verifier does learn the exact threshold that was proven and the scope it was proven for.
- In the demo app the secret is made with `crypto.getRandomValues`, kept in memory, never
  displayed and never sent anywhere. After the page and its Wasm file have loaded, the app makes
  no network requests, except when you click the optional **Use Zcash epoch as scope** button.
  That button asks this site's own server for the Zcash block height. The browser never
  contacts a third party, and nothing about the holder is sent. You can check this in your
  browser's Network tab.

---

## Relationship to Zcash

The proof uses the same family of building blocks as Zcash Orchard:

- Halo2 (`halo2_proofs`) with no trusted setup
- The Pallas and Vesta curves (`pasta_curves`)
- The Poseidon hash chip from `halo2_gadgets`, using the `P128Pow5T3` specification, which the
  library's own tests import under the name `OrchardNullifier`

**The only live link to Zcash is one optional, read-only call for the public block height**
(see the next section). The project does not scan notes, use a wallet, handle keys or
addresses, or verify anything on-chain. Zcash has no general smart contracts, so proofs are
verified off-chain by the verifier application.

### Optional: Zcash epoch as scope

Zcash mainnet targets one block every 75 seconds, so 1152 blocks is about one day. In the demo
the holder can click **Use Zcash epoch as scope**. The page asks this site's own server
(`apps/demo-dapp/api/zcash-tip.js`) for the current block height and sets
`scope = floor(height / 1152)`. The verifier window then offers a checkbox,
**Require scope = current Zcash epoch**.

The result is a verifier that allows **one claim per day**: the nullifier changes every epoch,
so a holder can claim again tomorrow, and claims on different days cannot be linked.

How the height is read:

- The server function asks the public CipherScan explorer API
  (`api.mainnet.cipherscan.app`) about one fixed old block. The explorer reports how many blocks
  have been built on top of it, so the tip is that block's height plus its confirmations, minus one.
- The function refuses an answer that does not match the time that has passed (within 10%).
- Only public chain data is requested. No keys, no addresses, no user data.

What this is not: it is trusted to one community API, not verified against a Zcash node, and the
demo verifier uses the epoch it loaded earlier instead of reading the chain itself. A real
verifier should compute the current epoch on its own.

### Zcash integration ideas (not built)

1. **A wallet-side issuer.** A Zcash wallet that already holds a viewing key could compute a
   balance locally and turn it into a credential, so a user could prove "I hold at least X ZEC"
   without publishing an address or an exact balance. This needs a light-client library and a
   careful design. The viewing key must stay on the user's device and must never be pasted into a
   web page.
2. **An issuer that signs the root.** The verifier would check an Ed25519 signature on the
   Merkle root outside the circuit, which ties the root to a named issuer.

Neither is implemented.

---

## Measured performance

Measured by the author, on one Windows PC in Chrome with the production build, over several
runs. These are not general benchmarks. Other machines will differ.

| Step | Browser (Chrome) | Native release build (2-core cloud server) |
| --- | --- | --- |
| Prover setup (once per page load) | about 7 to 12 s | about 1.2 s |
| Creating a proof | about 4.2 to 5.8 s | about 0.74 s |
| Verifying a proof | about 0.11 to 0.25 s | about 0.02 s |
| Proof size | 3,616 bytes | 3,616 bytes |

The Wasm file is 945 KB (348 KB compressed). The prover runs in a Web Worker, so the page keeps
responding while it works.

---

## Tests

**Rust** (`circuits`, run with `cargo test --release`): 25 tests across the circuits and the Wasm
API. Examples of what they check:

- the in-circuit Poseidon output matches an independent native Poseidon calculation
- valid Merkle paths are accepted; a wrong leaf, sibling, index bit or root is rejected
- a value below the threshold is rejected, including the wrap-around case
- a claimed value larger than the one in the leaf is rejected
- someone else's secret cannot open the leaf
- the same proof is rejected for a different scope or a different threshold
- real proofs are created and verified end to end

**SDK** (`packages/core`):

- 16 unit tests with a fake backend: argument order, input validation, the secret never leaving
  the holder, replay blocking, malformed input never reaching the prover, and the Zcash epoch
  helper
- 1 end-to-end test that runs the real Halo2 prover from Node through the SDK, including the
  attack cases

**Zcash height endpoint** (`apps/demo-dapp/test`): 5 tests with a faked upstream: the tip
calculation, an answer that fails the time check, malformed answers, upstream errors, and
non-GET requests. The live call to the explorer is not part of the automated tests.

The circuits have **not** had an independent security review. Treat this as a hackathon
prototype.

---

## Repository layout

```text
circuits/            Rust crate: Halo2 circuits and the Wasm API
  src/badge.rs         the combined circuit (the one that matters)
  src/merkle.rs        Merkle membership
  src/threshold.rs     64-bit range check
  src/nullifier.rs     scoped Poseidon nullifier
  src/mul_demo.rs      the first, smallest proof (a * b = c)
  src/wasm_api.rs      the functions JavaScript can call
  pkg/                 generated Wasm package (wasm-pack output)
packages/core/       TypeScript SDK (@shielded-badges/core), source only
apps/demo-dapp/      React + Vite demo: landing page and Issuer / Holder / Verifier desk
  api/zcash-tip.js     serverless function that reads the Zcash block height (Vercel)
```

---

## Run it

### Demo app

```powershell
cd apps/demo-dapp
npm install
npm run dev
```

The Zcash epoch button needs the serverless function, so it works on the deployed site but not
on `npm run dev`. Locally it shows a short error and the rest of the demo keeps working.
To test the function's logic: `node --test test/zcash-tip.test.js`.

**SDK tests** (Node 22.18 or newer; no install needed)

```powershell
cd packages/core
npm test
npm run test:integration
```

**Rust tests** (needs Rust. On Windows it also needs the Microsoft C++ build tools. A Linux
machine or GitHub Codespaces avoids that.)

```bash
cd circuits
cargo test --release -- --nocapture
```

### Rebuild the Wasm package

```bash
cd circuits
wasm-pack build --target web --release
```

Then copy the `shielded_badges_circuits*` files from `circuits/pkg` into
`apps/demo-dapp/src/wasm`.

---

## SDK usage

`@shielded-badges/core` is a source-only package. It is not published to npm.

```ts
import init, { BadgeProver, demo_tree, nullifier_hex } from "./wasm/shielded_badges_circuits.js";
import { createDirectBackend, createHolder, createVerifier } from "@shielded-badges/core";

const backend = createDirectBackend({
  init: () => init(),
  newProver: () => new BadgeProver(),
  demoTree: demo_tree,
  nullifierHex: nullifier_hex,
});

const holder = createHolder(backend);      // makes its own secret and never exposes it
const verifier = createVerifier(backend);  // has a built-in nullifier registry

await holder.ready();                      // first call takes several seconds

const credential = await holder.issueDemoCredential({ badgeType: 1, value: 750, index: 5 });
const bundle = await holder.prove({ credential, threshold: 500, scope: 99 });

await verifier.verify(bundle); // { status: "accepted", millis }
await verifier.verify(bundle); // { status: "rejected_replay", millis }
```

`verifier.verify` returns `accepted`, `rejected_invalid` or `rejected_replay`. It never throws on
malformed input. `verifier.check` verifies a proof without touching the registry.

To keep a page smooth, run `createDispatcher(wasm)` inside a Web Worker and talk to it with
`createWorkerBackend(worker)`. The demo app's own worker implements the same message format by
hand. Moving the demo app onto the SDK is not done yet.

---

## Limits and next steps

- The issuer is simulated and does not sign its root.
- The Wasm API has no `identity(secret)` function yet, so the demo issuer is given the secret.
- Each page runs the setup itself. There is no serialized verifying key yet.
- The tree depth is fixed at 4 (16 credentials). Values and thresholds must fit in 64 bits.
- No independent security review.
- The Zcash link is one optional, read-only height lookup through a single community API. There is no
  wallet, key, note-scanning or on-chain verification.

---

## License and credits

MIT. See `LICENSE`.

Built with `halo2_proofs` 0.4.0, `halo2_gadgets` 0.6.0 (which pulls in `halo2_poseidon`),
`pasta_curves` 0.6.1, `wasm-bindgen`, React and Vite.

All code in this repository was written during the ZECATHON build window. The git history starts
on 2026-10-13. Parts of the code and documentation were written with the help of an AI
assistant (Claude, by Anthropic).
