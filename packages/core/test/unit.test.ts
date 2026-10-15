import { test } from "node:test";
import assert from "node:assert/strict";
import {
  createDispatcher,
  createHolder,
  createNullifierRegistry,
  createVerifier,
  generateSecret,
  isFieldHex,
  toU64String,
} from "../src/index.ts";
import type { Backend, Method, ProofBundle, ProverReply, WasmApi } from "../src/index.ts";

const HEX64_A = "a".repeat(64);
const HEX64_B = "b".repeat(64);
const SECRET = "01".repeat(31) + "00";

type Call = { method: Method; args: string[] };

/** A fake backend that records every call and answers through `handler`. */
function mockBackend(handler: (method: Method, args: readonly string[]) => unknown) {
  const calls: Call[] = [];
  const backend: Backend = {
    async call(method, args): Promise<ProverReply> {
      calls.push({ method, args: [...args] });
      try {
        return { id: calls.length, ok: true, result: handler(method, args), ms: 1 };
      } catch (e) {
        return { id: calls.length, ok: false, error: String(e), ms: 1 };
      }
    },
    close() {},
  };
  return { backend, calls };
}

function holderBackend() {
  return mockBackend((method) => {
    if (method === "demo_tree") return `${HEX64_A};${HEX64_B},${HEX64_B},${HEX64_B},${HEX64_B};0,1,0,1`;
    if (method === "prove") return "beef";
    if (method === "nullifier") return HEX64_B;
    return true;
  });
}

test("toU64String accepts valid numbers", () => {
  assert.equal(toU64String(0, "x"), "0");
  assert.equal(toU64String(750, "x"), "750");
  assert.equal(toU64String(" 12345 ", "x"), "12345");
  assert.equal(toU64String(2n ** 64n - 1n, "x"), "18446744073709551615");
});

test("toU64String rejects bad numbers", () => {
  assert.throws(() => toU64String(-1, "x"), RangeError);
  assert.throws(() => toU64String(1.5, "x"), RangeError);
  assert.throws(() => toU64String(Number.NaN, "x"), RangeError);
  assert.throws(() => toU64String("abc", "x"), RangeError);
  assert.throws(() => toU64String("-5", "x"), RangeError);
  assert.throws(() => toU64String(2n ** 64n, "x"), RangeError);
  assert.throws(() => toU64String(null as unknown as number, "x"), TypeError);
});

test("generateSecret makes a valid, fresh field-sized secret", () => {
  const a = generateSecret();
  const b = generateSecret();
  assert.ok(isFieldHex(a));
  assert.ok(a.endsWith("00"));
  assert.notEqual(a, b);
});

test("nullifier registry is per scope", () => {
  const r = createNullifierRegistry();
  assert.equal(r.has("99", HEX64_A), false);
  r.add("99", HEX64_A);
  assert.equal(r.has("99", HEX64_A), true);
  assert.equal(r.has("99", HEX64_A.toUpperCase()), true);
  assert.equal(r.has("100", HEX64_A), false);
  assert.equal(r.size, 1);
  r.clear();
  assert.equal(r.size, 0);
});

test("holder sends arguments to the prover in the right order", async () => {
  const { backend, calls } = holderBackend();
  const holder = createHolder(backend, { secret: SECRET });
  const credential = await holder.issueDemoCredential({ badgeType: 1, value: 750, index: 5 });

  assert.deepEqual(calls[0], { method: "demo_tree", args: [SECRET, "1", "750", "5"] });
  assert.equal(credential.root, HEX64_A);
  assert.equal(credential.bits, "0,1,0,1");

  const result = await holder.prove({ credential, threshold: 500, scope: 99 });
  const proveCall = calls.find((c) => c.method === "prove");
  assert.deepEqual(proveCall?.args, [
    SECRET,
    "1",
    "750",
    "500",
    "99",
    HEX64_A,
    `${HEX64_B},${HEX64_B},${HEX64_B},${HEX64_B}`,
    "0,1,0,1",
  ]);
  assert.equal(result.proof, "beef");
  assert.deepEqual(result.publicInputs, {
    root: HEX64_A,
    badgeType: "1",
    threshold: "500",
    scope: "99",
    nullifier: HEX64_B,
  });
});

test("the secret never appears in anything the holder returns", async () => {
  const { backend } = holderBackend();
  const holder = createHolder(backend, { secret: SECRET });
  const credential = await holder.issueDemoCredential({ badgeType: 1, value: 750, index: 5 });
  const result = await holder.prove({ credential, threshold: 500, scope: 99 });
  assert.equal(JSON.stringify(credential).includes(SECRET), false);
  assert.equal(JSON.stringify(result).includes(SECRET), false);
  assert.equal("secret" in holder, false);
});

test("holder refuses a false claim unless told otherwise", async () => {
  const { backend } = holderBackend();
  const holder = createHolder(backend, { secret: SECRET });
  const credential = await holder.issueDemoCredential({ badgeType: 1, value: 750, index: 5 });

  await assert.rejects(holder.prove({ credential, threshold: 800, scope: 99 }), RangeError);
  const forced = await holder.prove({ credential, threshold: 800, scope: 99, allowFalseClaim: true });
  assert.equal(forced.publicInputs.threshold, "800");
});

test("holder validates its inputs", async () => {
  const { backend } = holderBackend();
  assert.throws(() => createHolder(backend, { secret: "nothex" }), RangeError);
  const holder = createHolder(backend, { secret: SECRET });
  await assert.rejects(holder.issueDemoCredential({ badgeType: 1, value: 750, index: 16 }), RangeError);
  await assert.rejects(holder.issueDemoCredential({ badgeType: 1, value: -1, index: 0 }), RangeError);
});

function bundle(scope = "99", nullifier = HEX64_B): ProofBundle {
  return {
    proof: "abcd",
    publicInputs: { root: HEX64_A, badgeType: "1", threshold: "500", scope, nullifier },
  };
}

test("verifier accepts once, then blocks the replay in the same scope", async () => {
  const { backend } = mockBackend(() => true);
  const verifier = createVerifier(backend);
  assert.equal((await verifier.verify(bundle())).status, "accepted");
  assert.equal((await verifier.verify(bundle())).status, "rejected_replay");
  assert.equal((await verifier.verify(bundle("100"))).status, "accepted");
});

test("verifier rejects invalid proofs without consuming the nullifier", async () => {
  let answer = false;
  const { backend } = mockBackend(() => answer);
  const verifier = createVerifier(backend);
  assert.equal((await verifier.verify(bundle())).status, "rejected_invalid");
  assert.equal(verifier.registry.size, 0);
  answer = true;
  assert.equal((await verifier.verify(bundle())).status, "accepted");
});

test("verifier treats malformed input as invalid and never throws", async () => {
  const { backend, calls } = mockBackend(() => true);
  const verifier = createVerifier(backend);

  const bad: ProofBundle[] = [
    { ...bundle(), proof: "xyz" },
    { ...bundle(), proof: "" },
    { proof: "abcd", publicInputs: { ...bundle().publicInputs, root: "short" } },
    { proof: "abcd", publicInputs: { ...bundle().publicInputs, nullifier: "short" } },
    { proof: "abcd", publicInputs: { ...bundle().publicInputs, threshold: "-1" } },
    { proof: "abcd", publicInputs: { ...bundle().publicInputs, scope: "1e9" } },
  ];
  for (const b of bad) {
    assert.equal((await verifier.verify(b)).status, "rejected_invalid");
  }
  assert.equal(calls.length, 0, "malformed input must not reach the prover");
});

test("check never touches the registry", async () => {
  const { backend } = mockBackend(() => true);
  const verifier = createVerifier(backend);
  assert.equal((await verifier.check(bundle())).valid, true);
  assert.equal((await verifier.check(bundle())).valid, true);
  assert.equal(verifier.registry.size, 0);
});

test("dispatcher routes calls, initialises once and reports errors", async () => {
  let inits = 0;
  let provers = 0;
  const wasm: WasmApi = {
    init: async () => {
      inits++;
    },
    newProver: () => {
      provers++;
      return {
        prove: () => "proofhex",
        verify: () => true,
        free() {},
      };
    },
    demoTree: () => "tree",
    nullifierHex: () => "nf",
  };
  const dispatch = createDispatcher(wasm);

  const early = await dispatch({ id: 1, method: "prove", args: [] });
  assert.equal(early.ok, false);
  assert.match(String(early.error), /not ready/);

  assert.equal((await dispatch({ id: 2, method: "init", args: [] })).ok, true);
  assert.equal((await dispatch({ id: 3, method: "init", args: [] })).ok, true);
  assert.equal(inits, 1);
  assert.equal(provers, 1);

  assert.equal((await dispatch({ id: 4, method: "prove", args: [] })).result, "proofhex");
  assert.equal((await dispatch({ id: 5, method: "demo_tree", args: ["s", "1", "2", "3"] })).result, "tree");
  assert.equal((await dispatch({ id: 6, method: "nullifier", args: ["s", "1", "2"] })).result, "nf");
  assert.equal((await dispatch({ id: 7, method: "verify", args: [] })).result, true);

  const unknown = await dispatch({ id: 8, method: "nope" as Method, args: [] });
  assert.equal(unknown.ok, false);
  assert.equal(unknown.id, 8);
});
