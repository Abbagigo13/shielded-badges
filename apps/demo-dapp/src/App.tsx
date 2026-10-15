import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import Landing from "./components/Landing";
import "./desk.css";

const BADGE = "1";
const INDEX = 5;
const MAX = 1_000_000;

type Reply = { id: number; ok: boolean; result?: unknown; error?: string; ms: number };
type Issued = { value: number; root: string; siblings: string; bits: string };
type Sent = {
  proof: string;
  root: string;
  threshold: number;
  scope: number;
  nullifier: string;
};
type Line = { kind: "ok" | "blocked" | "info"; text: string };

// 31 random bytes plus a zero byte keeps the number below the field limit.
function randomSecretHex(): string {
  const bytes = new Uint8Array(31);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return hex + "00";
}

function parseNum(s: string): number | null {
  const t = s.trim();
  if (!/^\d{1,7}$/.test(t)) return null;
  const n = Number(t);
  return n <= MAX ? n : null;
}

function need(r: Reply): Reply {
  if (!r.ok) throw new Error(r.error);
  return r;
}

const short = (hex: string) => `${hex.slice(0, 10)}...${hex.slice(-6)}`;
const ms = (n: number) => `${Math.round(n)} ms`;

function Win({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="window">
      <div className="titlebar">
        <span>{title}</span>
        <span>X</span>
      </div>
      <div className="window-body">{children}</div>
    </div>
  );
}

function App() {
  const workerRef = useRef<Worker | null>(null);
  const pendingRef = useRef(new Map<number, (r: Reply) => void>());
  const nextIdRef = useRef(1);
  const seenRef = useRef(new Set<string>());

  // The holder's secret. Created once, kept in memory, never displayed or sent anywhere.
  const [secret] = useState(randomSecretHex);

  const [screen, setScreen] = useState<"landing" | "desk">("landing");
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");
  const [bootMs, setBootMs] = useState<number | null>(null);
  const [busyLabel, setBusyLabel] = useState<string | null>(null);
  const [seconds, setSeconds] = useState(0);

  const [valueInput, setValueInput] = useState("750");
  const [thresholdInput, setThresholdInput] = useState("500");
  const [scopeInput, setScopeInput] = useState("99");

  const [issued, setIssued] = useState<Issued | null>(null);
  const [sent, setSent] = useState<Sent | null>(null);
  const [issuerNote, setIssuerNote] = useState("");
  const [holderNote, setHolderNote] = useState("");
  const [lines, setLines] = useState<Line[]>([]);

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
      setHolderNote(`ERROR in worker: ${e.message}`);
    };

    let cancelled = false;
    call("init").then((r) => {
      if (cancelled) return;
      if (r.ok) {
        setBootMs(r.ms);
        setStatus("ready");
      } else {
        setStatus("error");
        setHolderNote(`ERROR: ${r.error}`);
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

  const ready = status === "ready";
  const busy = busyLabel !== null;
  const addLine = (kind: Line["kind"], text: string) =>
    setLines((prev) => [...prev, { kind, text }]);

  async function withBusy(label: string, fn: () => Promise<void>) {
    setBusyLabel(label);
    try {
      await fn();
    } catch (e: unknown) {
      addLine("blocked", `ERROR: ${String(e)}`);
    } finally {
      setBusyLabel(null);
    }
  }

  const verifyOnce = async (
    proof: string,
    root: string,
    threshold: number,
    scope: number,
    nullifier: string,
  ) => {
    const r = await call("verify", [proof, root, BADGE, threshold, scope, nullifier]);
    return { valid: r.ok && r.result === true, ms: r.ms };
  };

  // ----- issuer -----
  const issue = () =>
    withBusy("Issuing credential", async () => {
      const v = parseNum(valueInput);
      if (v === null) {
        setIssuerNote("Enter a whole number from 0 to 1000000.");
        return;
      }
      const r = need(await call("demo_tree", [secret, BADGE, v, INDEX]));
      const [root, siblings, bits] = String(r.result).split(";");
      setIssued({ value: v, root, siblings, bits });
      setSent(null);
      setLines([]);
      seenRef.current.clear();
      setHolderNote("");
      setIssuerNote(`Credential issued with value ${v}. Only the Merkle root is published.`);
    });

  // ----- holder -----
  const createProof = () =>
    withBusy("Creating proof", async () => {
      if (!issued) return;
      const thr = parseNum(thresholdInput);
      const scope = parseNum(scopeInput);
      if (thr === null || scope === null) {
        setHolderNote("Threshold and scope must be whole numbers from 0 to 1000000.");
        return;
      }
      setLines([]);
      const r = await call("prove", [
        secret,
        BADGE,
        issued.value,
        thr,
        scope,
        issued.root,
        issued.siblings,
        issued.bits,
      ]);
      if (!r.ok) {
        setSent(null);
        setHolderNote(`The prover could not build a proof: ${r.error}`);
        return;
      }
      const nullifier = String(need(await call("nullifier", [secret, BADGE, scope])).result);
      const proof = String(r.result);
      setSent({ proof, root: issued.root, threshold: thr, scope, nullifier });
      setHolderNote(
        `Proof built in ${ms(r.ms)} (${proof.length / 2} bytes). The verifier now decides whether it is valid.`,
      );
    });

  // ----- verifier -----
  const verifyProof = () =>
    withBusy("Verifying", async () => {
      if (!sent) return;
      const v = await verifyOnce(sent.proof, sent.root, sent.threshold, sent.scope, sent.nullifier);
      if (!v.valid) {
        addLine(
          "blocked",
          `REJECTED (${ms(v.ms)}): the proof does not verify. Either the claim is false or the proof was altered.`,
        );
        return;
      }
      const key = `${sent.scope}:${sent.nullifier}`;
      if (seenRef.current.has(key)) {
        addLine(
          "blocked",
          `REJECTED (${ms(v.ms)}): the proof is valid, but this nullifier was already used in scope ${sent.scope}. Double claim blocked.`,
        );
        return;
      }
      seenRef.current.add(key);
      addLine(
        "ok",
        `ACCEPTED (${ms(v.ms)}): the holder has a credential from this issuer with a value of at least ${sent.threshold}. Nullifier recorded for scope ${sent.scope}.`,
      );
    });

  const attack = (label: string, run: (s: Sent) => Promise<{ valid: boolean; ms: number }>) =>
    withBusy("Verifying", async () => {
      if (!sent) return;
      const v = await run(sent);
      if (v.valid) {
        addLine("ok", `UNEXPECTED: "${label}" was ACCEPTED. This would be a soundness bug.`);
      } else {
        addLine("blocked", `ATTACK BLOCKED (${ms(v.ms)}): ${label}`);
      }
    });

  const attackScope = () =>
    attack("proof replayed in another scope", (s) =>
      verifyOnce(s.proof, s.root, s.threshold, s.scope + 1, s.nullifier),
    );

  const attackThreshold = () =>
    attack("proof claimed for a higher threshold", (s) =>
      verifyOnce(s.proof, s.root, s.threshold + 1, s.scope, s.nullifier),
    );

  const attackTamper = () =>
    attack("proof bytes tampered with", (s) => {
      const i = 200;
      const tampered =
        s.proof.slice(0, i) + (s.proof[i] === "0" ? "1" : "0") + s.proof.slice(i + 1);
      return verifyOnce(tampered, s.root, s.threshold, s.scope, s.nullifier);
    });

  if (screen === "landing") {
    return <Landing status={status} seconds={seconds} onEnter={() => setScreen("desk")} />;
  }

  const statusText =
    status === "loading"
      ? `PROVER: LOADING ${seconds.toFixed(1)} s`
      : status === "ready"
        ? `PROVER: READY${bootMs !== null ? ` (setup ${ms(bootMs)})` : ""}`
        : "PROVER: ERROR";

  return (
    <div className="desk">
      <div className="desk-main">
        <div style={{ width: "100%" }}>
          <div className="window how">
            <div className="titlebar">
              <span>HOW TO USE</span>
              <span>X</span>
            </div>
            <div className="window-body">
              <div className="muted">
                1. Issuer: set a credential value and issue it. 2. Holder: set a threshold and
                create a proof. 3. Verifier: verify it, then try the attack buttons. Demo
                notes: the issuer is simulated, the prover and verifier run in this one page,
                and there is no connection to the Zcash network. The proof uses Halo2, the
                Pasta curves and Poseidon, the same primitives family as Zcash Orchard.
              </div>
            </div>
          </div>

          {busyLabel && (
            <p className="busy">
              <span className="spinner" />
              {busyLabel}... {seconds.toFixed(1)} s
            </p>
          )}

          <div className="grid">
            <Win title="1. ISSUER (SIMULATED)">
              <div className="muted">
                Builds a Merkle tree of 16 credentials and publishes only its root.
              </div>
              <label className="label" htmlFor="value">
                CREDENTIAL VALUE (0 - 1000000)
              </label>
              <input
                id="value"
                className="field"
                inputMode="numeric"
                value={valueInput}
                onChange={(e) => setValueInput(e.target.value)}
                disabled={busy}
              />
              <div className="btn-row">
                <button className="btn small" onClick={issue} disabled={!ready || busy}>
                  ISSUE CREDENTIAL
                </button>
              </div>
              {issued && (
                <div className="panel">
                  <div className="head">PUBLISHED BY ISSUER</div>
                  <div>Merkle root: {short(issued.root)}</div>
                </div>
              )}
              {issuerNote && <div className="note">{issuerNote}</div>}
            </Win>

            <Win title="2. HOLDER">
              <div className="muted">
                Only you see this window. Your secret and credential value never leave this page.
              </div>
              <div className="panel">
                <div className="head">PRIVATE</div>
                {issued ? (
                  <div className="private">Credential value: {issued.value}</div>
                ) : (
                  <div className="muted">No credential yet. Use the issuer window first.</div>
                )}
              </div>
              <label className="label" htmlFor="threshold">
                PROVE VALUE IS AT LEAST (THRESHOLD)
              </label>
              <input
                id="threshold"
                className="field"
                inputMode="numeric"
                value={thresholdInput}
                onChange={(e) => setThresholdInput(e.target.value)}
                disabled={busy}
              />
              <label className="label" htmlFor="scope">
                SCOPE (WHICH VERIFIER OR CAMPAIGN)
              </label>
              <input
                id="scope"
                className="field"
                inputMode="numeric"
                value={scopeInput}
                onChange={(e) => setScopeInput(e.target.value)}
                disabled={busy}
              />
              <div className="btn-row">
                <button
                  className="btn small"
                  onClick={createProof}
                  disabled={!ready || busy || !issued}
                >
                  CREATE PROOF
                </button>
              </div>
              {holderNote && <div className="note">{holderNote}</div>}
            </Win>

            <Win title="3. VERIFIER">
              <div className="muted">
                Receives a proof and public values. Nothing else.
              </div>
              {sent ? (
                <div className="panel">
                  <div className="head">RECEIVED</div>
                  <div>Proof: {sent.proof.length / 2} bytes</div>
                  <div>Merkle root: {short(sent.root)}</div>
                  <div>Threshold: {sent.threshold}</div>
                  <div>Scope: {sent.scope}</div>
                  <div>Nullifier: {short(sent.nullifier)}</div>
                  <div className="head" style={{ marginTop: 10 }}>
                    CANNOT SEE
                  </div>
                  <div>The secret, the credential value, or which of the 16 leaves is yours.</div>
                </div>
              ) : (
                <div className="panel muted">Waiting for a proof from the holder.</div>
              )}
              <div className="btn-row">
                <button className="btn small" onClick={verifyProof} disabled={!sent || busy}>
                  VERIFY PROOF
                </button>
              </div>
              <div className="label">ATTACKS (EACH SHOULD BE BLOCKED)</div>
              <div className="btn-row">
                <button className="btn small" onClick={attackScope} disabled={!sent || busy}>
                  REPLAY IN OTHER SCOPE
                </button>
                <button className="btn small" onClick={attackThreshold} disabled={!sent || busy}>
                  CLAIM HIGHER THRESHOLD
                </button>
                <button className="btn small" onClick={attackTamper} disabled={!sent || busy}>
                  TAMPER WITH PROOF
                </button>
              </div>
              <div className="results">
                {lines.map((l, i) => (
                  <div key={i} className={`line-${l.kind}`}>
                    {l.text}
                  </div>
                ))}
              </div>
            </Win>
          </div>
        </div>
      </div>

      <div className="taskbar">
        <span className="start">START</span>
        <span>ISSUER</span>
        <span>HOLDER</span>
        <span>VERIFIER</span>
        <span className="spacer" />
        <span>{statusText}</span>
      </div>
    </div>
  );
}

export default App;