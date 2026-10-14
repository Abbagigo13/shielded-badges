import init, {
  BadgeProver,
  demo_tree,
  nullifier_hex,
} from "./wasm/shielded_badges_circuits.js";

type Request = { id: number; method: string; args: string[] };

// Typed by hand so this file compiles without the special worker type library.
const ctx = self as unknown as {
  onmessage: ((e: MessageEvent<Request>) => void) | null;
  postMessage: (message: unknown) => void;
};

let prover: BadgeProver | null = null;

function needProver(): BadgeProver {
  if (!prover) throw new Error("prover is not ready yet");
  return prover;
}

ctx.onmessage = async (e: MessageEvent<Request>) => {
  const { id, method, args } = e.data;
  const t0 = performance.now();
  try {
    let result: unknown;
    switch (method) {
      case "init":
        await init();
        prover = new BadgeProver();
        result = true;
        break;
      case "demo_tree":
        result = demo_tree(args[0], args[1], args[2], Number(args[3]));
        break;
      case "nullifier":
        result = nullifier_hex(args[0], args[1], args[2]);
        break;
      case "prove":
        result = needProver().prove(
          args[0],
          args[1],
          args[2],
          args[3],
          args[4],
          args[5],
          args[6],
          args[7],
        );
        break;
      case "verify":
        result = needProver().verify(args[0], args[1], args[2], args[3], args[4], args[5]);
        break;
      default:
        throw new Error(`unknown method: ${method}`);
    }
    ctx.postMessage({ id, ok: true, result, ms: performance.now() - t0 });
  } catch (err) {
    ctx.postMessage({ id, ok: false, error: String(err), ms: performance.now() - t0 });
  }
};