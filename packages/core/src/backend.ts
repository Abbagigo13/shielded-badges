import type { Backend, ProverReply, ProverRequest } from "./types.ts";

/** The calls on one prover instance. Matches the generated BadgeProver class. */
export interface ProverLike {
  prove(
    secret: string,
    badge: string,
    value: string,
    threshold: string,
    scope: string,
    root: string,
    siblings: string,
    bits: string,
  ): string;
  verify(
    proof: string,
    root: string,
    badge: string,
    threshold: string,
    scope: string,
    nullifier: string,
  ): boolean;
  free(): void;
}

/**
 * What the SDK needs from the generated Wasm package. Wire it up like this:
 *
 *   import init, { BadgeProver, demo_tree, nullifier_hex } from "./wasm/shielded_badges_circuits.js";
 *   const wasm = {
 *     init: () => init(),
 *     newProver: () => new BadgeProver(),
 *     demoTree: demo_tree,
 *     nullifierHex: nullifier_hex,
 *   };
 */
export interface WasmApi {
  init: () => Promise<unknown>;
  newProver: () => ProverLike;
  demoTree: (secret: string, badge: string, value: string, index: number) => string;
  nullifierHex: (secret: string, badge: string, scope: string) => string;
}

/**
 * Turns a request into a reply by calling the Wasm functions. Use it inside a Web Worker
 * (so the page stays smooth) or through createDirectBackend.
 */
export function createDispatcher(wasm: WasmApi): (req: ProverRequest) => Promise<ProverReply> {
  let prover: ProverLike | null = null;
  const need = (): ProverLike => {
    if (!prover) throw new Error("prover is not ready yet");
    return prover;
  };

  return async (req) => {
    const t0 = performance.now();
    try {
      const a = req.args;
      let result: unknown;
      switch (req.method) {
        case "init":
          // Safe to call more than once: the slow setup only runs the first time.
          if (!prover) {
            await wasm.init();
            prover = wasm.newProver();
          }
          result = true;
          break;
        case "demo_tree":
          result = wasm.demoTree(a[0], a[1], a[2], Number(a[3]));
          break;
        case "nullifier":
          result = wasm.nullifierHex(a[0], a[1], a[2]);
          break;
        case "prove":
          result = need().prove(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
          break;
        case "verify":
          result = need().verify(a[0], a[1], a[2], a[3], a[4], a[5]);
          break;
        default:
          throw new Error(`unknown method: ${String(req.method)}`);
      }
      return { id: req.id, ok: true, result, ms: performance.now() - t0 };
    } catch (err) {
      return { id: req.id, ok: false, error: String(err), ms: performance.now() - t0 };
    }
  };
}

/** Runs the prover on the calling thread. Simple, but it blocks while a proof is built. */
export function createDirectBackend(wasm: WasmApi): Backend {
  const dispatch = createDispatcher(wasm);
  let nextId = 1;
  return {
    call: (method, args) => dispatch({ id: nextId++, method, args: [...args] }),
    close() {},
  };
}

/**
 * Talks to a Web Worker that runs createDispatcher. The worker must answer each request
 * with a ProverReply that carries the same id.
 */
export function createWorkerBackend(worker: Worker): Backend {
  const pending = new Map<number, (reply: ProverReply) => void>();
  let nextId = 1;

  worker.onmessage = (e: MessageEvent<ProverReply>) => {
    const resolve = pending.get(e.data.id);
    if (resolve) {
      pending.delete(e.data.id);
      resolve(e.data);
    }
  };

  worker.onerror = (e: ErrorEvent) => {
    for (const [id, resolve] of pending) {
      resolve({ id, ok: false, error: `worker error: ${e.message}`, ms: 0 });
    }
    pending.clear();
  };

  return {
    call: (method, args) =>
      new Promise<ProverReply>((resolve) => {
        const id = nextId++;
        pending.set(id, resolve);
        const req: ProverRequest = { id, method, args: [...args] };
        worker.postMessage(req);
      }),
    close() {
      worker.terminate();
      pending.clear();
    },
  };
}
