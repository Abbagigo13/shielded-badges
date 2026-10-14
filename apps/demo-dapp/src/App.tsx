import { useCallback, useEffect, useRef, useState } from "react";

const BADGE = "1";
const VALUE = "750";
const THRESHOLD = "500";
const SCOPE = "99";
const INDEX = 5;

type Reply = { id: number; ok: boolean; result?: unknown; error?: string; ms: number };

// 31 random bytes plus a zero byte keeps the number below the field limit.
function randomSecretHex(): string {
  const bytes = new Uint8Array(31);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return hex + "00";
}

const short = (hex: string) => `${hex.slice(0, 12)}...${hex.slice(-6)}`;
const ms = (n: number) => `${Math.round(n)} ms`;

function App() {
  const workerRef = useRef<Worker | null>(null);
  const pendingRef = useRef(new Map<number, (r: Reply) => void>());
  const nextIdRef = useRef(1);

  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");
  const [bootMs, setBootMs] = useState<number | null>(null);
  const [busyLabel, setBusyLabel] = useState<string | null>(null);
  const [seconds, setSeconds] = useState(0);
  const [log, setLog] = useState<string[]>([]);
  const [running, setRunning] = useState(false);

  // Sends one request to the worker and waits for its reply.
  const call = useCallback(
    (method: string, args: (string | number)[] = []) =>
      new Promise<Reply>((resolve) => {
        const id = nextIdRef.current++;
        pendingRef.current.set(id, resolve);
        workerRef.current?.postMessage({ id, method, args: args.map(String) });
      }),
    [],
  );

  // Start the worker and load the prover as soon as the page opens.
  useEffect(() => {
    const worker = new Worker(new URL("./prover.worker.ts", import.meta.url), {
      type: "module",
    });
    workerRef.current = worker;
    const pending = pendingRef.current;

    worker.onmessage = (e: MessageEvent<Reply>) => {
      const resolve = pending.get(e.data.id);
      if (resolve) {
        pending.delete(e.data.id);
        resolve(e.data);
      }
    };
    worker.onerror = (e) => {
      setStatus("error");
      setLog([`ERROR in worker: ${e.message}`]);
    };

    let cancelled = false;
    call("init").then((r) => {
      if (cancelled) return;
      if (r.ok) {
        setBootMs(r.ms);
        setStatus("ready");
      } else {
        setStatus("error");
        setLog([`ERROR: ${r.error}`]);
      }
    });

    return () => {
      cancelled = true;
      worker.terminate();
      pending.clear();
    };
  }, [call]);

  // A ticking timer that keeps moving only if the page is NOT frozen.
  useEffect(() => {
    if (status !== "loading" && !busyLabel) return;
    const start = performance.now();
    const timer = setInterval(() => setSeconds((performance.now() - start) / 1000), 100);
    return () => clearInterval(timer);
  }, [status, busyLabel]);

  async function runDemo() {
    setRunning(true);
    setLog([]);
    const add = (line: string) => setLog((prev) => [...prev, line]);
    const need = (r: Reply): Reply => {
      if (!r.ok) throw new Error(r.error);
      return r;
    };
    const verify = async (
      proof: string,
      root: string,
      threshold: string,
      scope: string,
      nullifier: string,
    ) => {
      const r = await call("verify", [proof, root, BADGE, threshold, scope, nullifier]);
      return { ok: r.ok && r.result === true, ms: r.ms };
    };
    const check = (label: string, got: boolean, want: boolean) =>
      add(`${got === want ? "PASS" : "FAIL"}  ${label}`);

    try {
      const secret = randomSecretHex();
      add("Random secret generated in this page. It is never displayed or sent anywhere.");

      const treeReply = need(await call("demo_tree", [secret, BADGE, VALUE, INDEX]));
      const [root, siblings, bits] = String(treeReply.result).split(";");
      add(`Issuer tree built, root: ${short(root)}`);

      const nullifier = String(need(await call("nullifier", [secret, BADGE, SCOPE])).result);
      add(`Nullifier for scope ${SCOPE}: ${short(nullifier)}`);

      add(`Creating proof: value is at least ${THRESHOLD} (real value hidden)...`);
      setBusyLabel("Creating proof");
      const proofReply = need(
        await call("prove", [secret, BADGE, VALUE, THRESHOLD, SCOPE, root, siblings, bits]),
      );
      setBusyLabel(null);
      const proof = String(proofReply.result);
      add(`Proof created: ${ms(proofReply.ms)}, size ${proof.length / 2} bytes`);

      const honest = await verify(proof, root, THRESHOLD, SCOPE, nullifier);
      add(`Verification time: ${ms(honest.ms)}`);
      check("honest proof is accepted", honest.ok, true);

      const otherNullifier = String(need(await call("nullifier", [secret, BADGE, "100"])).result);
      check(
        "same proof claimed for a different scope is rejected",
        (await verify(proof, root, THRESHOLD, "100", otherNullifier)).ok,
        false,
      );

      check(
        "same proof claimed for a higher threshold (600) is rejected",
        (await verify(proof, root, "600", SCOPE, nullifier)).ok,
        false,
      );

      const i = 200;
      const tampered = proof.slice(0, i) + (proof[i] === "0" ? "1" : "0") + proof.slice(i + 1);
      check(
        "tampered proof is rejected",
        (await verify(tampered, root, THRESHOLD, SCOPE, nullifier)).ok,
        false,
      );

      add("Done.");
    } catch (e: unknown) {
      add(`ERROR: ${String(e)}`);
    } finally {
      setBusyLabel(null);
      setRunning(false);
    }
  }

  return (
    <div style={{ fontFamily: "monospace", padding: 32, maxWidth: 900, margin: "0 auto" }}>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>

      <h1>ShieldedBadges proof demo</h1>
      <p>
        Proves, in your browser, that a credential in the issuer&apos;s tree has a value of at
        least {THRESHOLD}, without revealing the secret, the value or which leaf is yours.
      </p>
      <p>
        Demo note: the prover and the verifier run in the same page here. In real use they
        would be separate parties.
      </p>

      {(status === "loading" || busyLabel) && (
        <div style={{ display: "flex", alignItems: "center", gap: 16, margin: "16px 0" }}>
          <div
            style={{
              width: 24,
              height: 24,
              border: "3px solid #4ff0a0",
              animation: "spin 1s linear infinite",
            }}
          />
          <div>
            {status === "loading" ? "LOADING HALO2 PROVER..." : `${busyLabel}...`}{" "}
            {seconds.toFixed(1)} s
          </div>
        </div>
      )}

      {status === "ready" && bootMs !== null && (
        <p>Prover ready (setup took {ms(bootMs)}, off the main thread).</p>
      )}

      <button
        onClick={runDemo}
        disabled={status !== "ready" || running}
        style={{ padding: "8px 16px" }}
      >
        {status === "loading"
          ? "Loading prover..."
          : running
            ? "Running..."
            : "Run proof demo"}
      </button>

      <pre style={{ marginTop: 24, whiteSpace: "pre-wrap" }}>{log.join("\n")}</pre>
    </div>
  );
}

export default App;