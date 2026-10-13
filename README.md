# ShieldedBadges

**Private reputation and credential proofs, built on the same primitives as Zcash Orchard.**

Built for ZECATHON (Core & Tooling track, with a Wildcard-track demo).

---

## What it does

ShieldedBadges lets a person prove a fact about themselves, such as "I hold at least 10 of X", "I merged at least 50 pull requests" or "I have DAO voting rights", without revealing who they are, which wallet they use, or the exact number behind the claim.

A verifier (a dApp, a DAO portal, a community gate) learns exactly one thing: the claim is true and has not been used twice in the same context.

## The problem

Today's credentials (Soulbound Tokens, POAPs, public wallet history) are tied to one public address. Proving a threshold means exposing the exact balance or identity behind it, and anyone can link a user's activity across sites.

## How it works

Three parties:

1. **Issuer** (a DAO, a GitHub bot, a protocol). Builds a Merkle tree of credential leaves and signs the **Merkle root** with Ed25519. Raw credential data is never published.
2. **Holder** (the user). Generates a Halo2 proof **locally in the browser (Wasm)** that their private credential is in the issuer's tree and meets the threshold.
3. **Verifier** (any app). Checks the issuer's signature on the root, verifies the proof, and records the nullifier to block double-claims.

```text
 Issuer                      Holder (browser)                  Verifier
   |                               |                              |
   | 1. credential leaf + root     |                              |
   |    signed (Ed25519)           |                              |
   |------------------------------>|                              |
   |                               | 2. Halo2 proof (Wasm):       |
   |                               |    membership + value >=     |
   |                               |    threshold + nullifier     |
   |                               |----------------------------->|
   |                               |                              | 3. verify signature on root
   |                               |                              |    verify proof
   |                               |                              |    check nullifier unused
```

### What the circuit proves

Private inputs: `secret`, `value`, Merkle path.
Public inputs: `merkle_root`, `badge_type`, `threshold`, `scope`, `nullifier`.

- `idCommitment = Poseidon(secret)`
- `leaf = Poseidon(idCommitment, badge_type, value)`
- `leaf` is a member of the tree with root `merkle_root`
- `value >= threshold` (range-checked)
- `nullifier = Poseidon(secret, badge_type, scope)`

The Ed25519 signature on the root is checked by the verifier **outside** the circuit. Verifying Ed25519 inside a ZK circuit is very expensive, and signing the root keeps the circuit small.

### Nullifier and `scope`

The nullifier includes a `scope` (an identifier for the verifier or campaign). This gives two properties:

- The same holder cannot claim the same badge twice **within one scope**.
- The same holder produces **different, unlinkable** nullifiers in different scopes, so two verifiers cannot tell they saw the same person.

Without `scope`, a nullifier would be identical everywhere and act as a global tracking ID.

## Cryptographic stack

- **Proving system:** Halo2 (PLONKish, no trusted setup), the proving system used by Zcash Orchard.
- **Curves and hash:** Pasta curves (Pallas/Vesta) and Poseidon, the same family Orchard uses.
- **Issuer signatures:** Ed25519 over the Merkle root (off-circuit).
- **Client:** Rust circuit compiled to Wasm, driven by a TypeScript SDK.

## Honest scope and limitations

- Zcash has no general smart contracts, so proofs are verified **off-chain by the verifier** (an app or server), not by a Zcash on-chain contract.
- The demo uses a **mock issuer**. A real "holds N ZEC" issuer would need a wallet-side attestation flow using the user's own viewing key. That is future work.
- Performance numbers (proving and verification time) will be published here only after they are measured.

## Roadmap

- [ ] Phase 1: Halo2 circuit (membership, threshold, nullifier) and `@shielded-badges/core` TypeScript SDK
- [ ] Phase 2: React demo dApp with in-browser proving
- [ ] Phase 3: Wallet and browser-extension integration, real issuers, anonymous DAO voting

## Project structure

```text
shielded-badges/
├── README.md
├── package.json
├── packages/
│   └── core/                  # TypeScript SDK
│       └── src/
│           ├── index.ts
│           ├── types.ts
│           ├── issuer.ts
│           ├── prover.ts
│           └── verifier.ts
├── circuits/                  # Rust + halo2_proofs, built to Wasm
│   ├── Cargo.toml
│   └── src/lib.rs
└── apps/
    └── demo-dapp/             # React + Vite
        └── src/
            ├── App.tsx
            ├── index.tsx
            └── components/
                └── ShieldedBadgeDemo.tsx
```

## Frontend style

The demo dApp follows the retro 1990s terminal look of the ZECATHON site: a dark green-black background, bright green monospace text, window frames with a striped title bar, a left icon sidebar and a bottom taskbar with a START button.
