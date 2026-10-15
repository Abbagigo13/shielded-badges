type Props = {
  status: "loading" | "ready" | "error";
  seconds: number;
  onEnter: () => void;
};

const COLS = 28;
const GLYPHS = "01ABCDEF23456789";
const RING_RADII = [70, 115, 160, 205, 250];

function hexPoints(cx: number, cy: number, r: number): string {
  return Array.from({ length: 6 }, (_, i) => {
    const a = (Math.PI / 3) * i - Math.PI / 6;
    return `${(cx + r * Math.cos(a)).toFixed(1)},${(cy + r * Math.sin(a)).toFixed(1)}`;
  }).join(" ");
}

export default function Landing({ status, seconds, onEnter }: Props) {
  // Falling hex glyphs: deterministic, so every visit looks the same.
  const rain = Array.from({ length: COLS }, (_, i) => ({
    x: 20 + (i * 760) / (COLS - 1),
    text: Array.from({ length: 12 }, (_, j) => GLYPHS[(i * 7 + j * 3) % GLYPHS.length]).join(""),
    delay: -((i * 37) % 11),
    duration: 9 + ((i * 13) % 8),
  }));

  const statusText =
    status === "loading"
      ? `LOADING HALO2 PROVER... ${seconds.toFixed(1)} s`
      : status === "ready"
        ? "PROVER READY"
        : "PROVER FAILED TO LOAD";

  return (
    <div className="landing">
      <svg viewBox="0 0 800 600" preserveAspectRatio="xMidYMid slice" aria-hidden="true">
        {/* falling glyphs */}
        {rain.map((c, i) => (
          <text
            key={i}
            className="rain"
            x={c.x}
            y={0}
            style={{
              writingMode: "vertical-rl",
              textOrientation: "upright",
              animationDuration: `${c.duration}s`,
              animationDelay: `${c.delay}s`,
            }}
          >
            {c.text}
          </text>
        ))}

        {/* rotating hexagon rings */}
        {RING_RADII.map((r, i) => (
          <g
            key={r}
            className={i % 2 ? "ring rev" : "ring"}
            style={{ animationDuration: `${24 + i * 10}s` }}
          >
            <polygon
              points={hexPoints(400, 300, r)}
              fill="none"
              stroke="#4ff0a0"
              strokeOpacity={0.55 - i * 0.08}
              strokeWidth={1.2}
              strokeDasharray={i % 2 ? "6 10" : "none"}
            />
          </g>
        ))}

        {/* the shield */}
        <g className="shield">
          <path
            d="M400 215 L468 240 L468 305 C468 350 438 378 400 392 C362 378 332 350 332 305 L332 240 Z"
            fill="#03120a"
            stroke="#4ff0a0"
            strokeWidth={2.5}
          />
          <polyline
            points="368,300 392,324 436,272"
            fill="none"
            stroke="#4ff0a0"
            strokeWidth={5}
            strokeLinecap="square"
          />
        </g>
      </svg>

      <div className="landing-content">
        <h1 className="title">SHIELDEDBADGES</h1>
        <p className="tag">
          Prove a credential, not an identity. Zero-knowledge reputation proofs built on
          Halo2, running entirely in your browser.
        </p>
        <div className="status">{statusText}</div>
        <button className="btn" onClick={onEnter}>
          ENTER
        </button>
      </div>
    </div>
  );
}