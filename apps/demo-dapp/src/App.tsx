import { useEffect, useState } from "react";
import init, { hello, add } from "./wasm/shielded_badges_circuits.js";

function App() {
  const [message, setMessage] = useState("LOADING WASM...");
  const [sum, setSum] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    init()
      .then(() => {
        setMessage(hello());
        setSum(add(2, 3));
      })
      .catch((e: unknown) => setError(String(e)));
  }, []);

  return (
    <div style={{ fontFamily: "monospace", padding: 32 }}>
      <h1>ShieldedBadges Wasm test</h1>
      <p>Message from Rust: {message}</p>
      <p>Rust says 2 + 3 = {sum === null ? "..." : sum}</p>
      {error && <p style={{ color: "red" }}>Error: {error}</p>}
    </div>
  );
}

export default App;