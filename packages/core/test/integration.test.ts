import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createDirectBackend, createHolder, createVerifier } from "../src/index.ts";

// Runs the REAL Halo2 prover (the Wasm package in circuits/pkg) through the SDK, in Node.
const pkgDir = fileURLToPath(new URL("../../../circuits/pkg/", import.meta.url));
const wasmFile = pkgDir + "shielded_badges_circuits_bg.wasm";

test(
  "real prover, end to end through the SDK",
  { skip: !existsSync(wasmFile) && "circuits/pkg not found", timeout: 300_000 },
  async () => {
    const glue = await import(pathToFileURL(pkgDir + "shielded_badges_circuits.js").href);
    const bytes = readFileSync(wasmFile);

    const backend = createDirectBackend({
      init: () => glue.default({ module_or_path: bytes }),
      newProver: () => new glue.BadgeProver(),
      demoTree: glue.demo_tree,
      nullifierHex: glue.nullifier_hex,
    });

    const holder = createHolder(backend);
    const verifier = createVerifier(backend);

    let t = performance.now();
    await holder.ready();
    await verifier.ready(); // instant: the prover is already loaded
    console.log(`setup: ${Math.round(performance.now() - t)} ms`);

    const credential = await holder.issueDemoCredential({ badgeType: 1, value: 750, index: 5 });

    t = performance.now();
    const bundle = await holder.prove({ credential, threshold: 500, scope: 99 });
    console.log(`prove: ${Math.round(performance.now() - t)} ms, ${bundle.proof.length / 2} bytes`);

    // honest proof is accepted once, then the replay is blocked
    assert.equal((await verifier.verify(bundle)).status, "accepted");
    assert.equal((await verifier.verify(bundle)).status, "rejected_replay");

    // attack: replay the proof in another scope
    const otherScope = { ...bundle, publicInputs: { ...bundle.publicInputs, scope: "100" } };
    assert.equal((await verifier.verify(otherScope)).status, "rejected_invalid");

    // attack: claim a higher threshold
    const higher = { ...bundle, publicInputs: { ...bundle.publicInputs, threshold: "501" } };
    assert.equal((await verifier.verify(higher)).status, "rejected_invalid");

    // attack: tamper with the proof
    const i = 200;
    const tampered = bundle.proof.slice(0, i) + (bundle.proof[i] === "0" ? "1" : "0") + bundle.proof.slice(i + 1);
    assert.equal((await verifier.verify({ ...bundle, proof: tampered })).status, "rejected_invalid");

    // the same holder in a different scope: accepted, with a different nullifier
    const second = await holder.prove({ credential, threshold: 500, scope: 100 });
    assert.notEqual(second.publicInputs.nullifier, bundle.publicInputs.nullifier);
    assert.equal((await verifier.verify(second)).status, "accepted");

    // a false claim: the holder refuses by default, and a forced one is rejected
    await assert.rejects(holder.prove({ credential, threshold: 800, scope: 101 }), RangeError);
    const forced = await holder.prove({ credential, threshold: 800, scope: 101, allowFalseClaim: true });
    assert.equal((await verifier.verify(forced)).status, "rejected_invalid");
  },
);
