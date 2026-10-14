import { useState } from "react";
import init, {
  BadgeProver,
  demo_tree,
  nullifier_hex,
} from "./wasm/shielded_badges_circuits.js";

const BADGE = "1";
const VALUE = "750";
const THRESHOLD = "500";
const SCOPE = "99";
const INDEX = 5;

// 31 random bytes plus a zero byte keeps the number below the field limit.
function randomSecretHex(): string {
  const bytes = new Uint8Array(31);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return hex + "00";
}

// Gives the browser a moment to paint the log before a heavy call freezes the page.
const nextFrame = () => new Promise<void>((resolve) => setTimeout(resolve, 50));
const elapsed = (t0: number) => `${Math.round(performance.now() - t0)} ms`;
const short = (hex: string) => `${hex.slice(0, 12)}...${hex.slice(-6)}`;

function App() {
  const [log, setLog] = useState<string[]>([]);
  const [running, setRunning] = useState(false);

  async function runDemo() {
    setRunning(true);
    setLog([]);
    const add = (line: string) => setLog((prev) => [...prev, line]);
    const check = (label: string, got: boolean, want: boolean) =>
      add(`${got === want ? "PASS" : "FAIL"}  ${label}`);

    try {
      let t = performance.now();
      await init();
      add(`Wasm loaded: ${elapsed(t)}`);

      const secret = randomSecretHex();
      add(`Random secret generated (stays in this page): ${short(secret)}`);

      const tree = demo_tree(secret, BADGE, VALUE, INDEX).split(";");
      const [root, siblings, bits] = tree;
      add(`Issuer tree built, root: ${short(root)}`);

      const nullifier = nullifier_hex(secret, BADGE, SCOPE);
      add(`Nullifier for scope ${SCOPE}: ${short(nullifier)}`);

      add("Running prover setup (key generation)...");
      await nextFrame();
      t = performance.now();
      const prover = new BadgeProver();
      add(`Prover setup: ${elapsed(t)}`);

      add(`Creating proof: value is at least ${THRESHOLD} (real value hidden)...`);
      await nextFrame();
      t = performance.now();
      const proof = prover.prove(
        secret,
        BADGE,
        VALUE,
        THRESHOLD,
        SCOPE,
        root,
        siblings,
        bits,
      );
      add(`Proof created: ${elapsed(t)}, size ${proof.length / 2} bytes`);

      await nextFrame();
      t = performance.now();
      const honest = prover.verify(proof, root, BADGE, THRESHOLD, SCOPE, nullifier);
      add(`Verification time: ${elapsed(t)}`);
      check("honest proof is accepted", honest, true);

      const otherNullifier = nullifier_hex(secret, BADGE, "100");
      check(
        "same proof claimed for a different scope is rejected",
        prover.verify(proof, root, BADGE, THRESHOLD, "100", otherNullifier),
        false,
      );

      check(
        "same proof claimed for a higher threshold (600) is rejected",
        prover.verify(proof, root, BADGE, "600", SCOPE, nullifier),
        false,
      );

      const i = 200;
      const tampered =
        proof.slice(0, i) + (proof[i] === "0" ? "1" : "0") + proof.slice(i + 1);
      let tamperedResult = false;
      try {
        tamperedResult = prover.verify(tampered, root, BADGE, THRESHOLD, SCOPE, nullifier);
      } catch {
        tamperedResult = false;
      }
      check("tampered proof is rejected", tamperedResult, false);

      prover.free();
      add("Done.");
    } catch (e: unknown) {
      add(`ERROR: ${String(e)}`);
    } finally {
      setRunning(false);
    }
  }

  return (
    <div style={{ fontFamily: "monospace", padding: 32, maxWidth: 900, margin: "0 auto" }}>
      <h1>ShieldedBadges proof demo</h1>
      <p>
        Proves, in your browser, that a credential in the issuer&apos;s tree has a value of at
        least {THRESHOLD}, without revealing the secret, the value or which leaf is yours.
      </p>
      <p>
        Demo note: the prover and the verifier run in the same page here. In real use they
        would be separate parties.
      </p>
      <button onClick={runDemo} disabled={running} style={{ padding: "8px 16px" }}>
        {running ? "Running (the page may freeze for a few seconds)..." : "Run proof demo"}
      </button>
      <pre style={{ marginTop: 24, whiteSpace: "pre-wrap" }}>{log.join("\n")}</pre>
    </div>
  );
}

export default App;