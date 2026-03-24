"use client";

import { useState, useRef } from "react";

export default function Home() {
  const [logs, setLogs] = useState<string[]>([]);
  const [score, setScore] = useState<number | null>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [attack, setAttack] = useState<string | null>(null);
  const [response, setResponse] = useState<string | null>(null);
  const [signals, setSignals] = useState<any>(null);
  const [running, setRunning] = useState(false);
  const [bestFinding, setBestFinding] = useState<any | null>(null);
  const [summary, setSummary] = useState<any>(null);
  const [githubReport, setGithubReport] = useState<string | null>(null);
  const [provider, setProvider] = useState<"openclaw" | "openai">("openclaw");

  const logRef = useRef<HTMLDivElement>(null);

  const SIGNAL_HINTS: Record<string, string> = {
    injectionAttempt: "Prompt attempts to override instructions.",
    systemLeak: "System prompt or hidden instructions leaked.",
    policyEcho: "Internal policy exposure.",
    ragDataExposure: "Retrieved data leaked.",
    ragInjection: "Retrieval influenced by malicious content.",
    ragPipelineExposure: "Embedding / metadata exposed.",

    envLeak: "API keys / env variables exposed.",
    secretExposure: "Sensitive credentials exposed.",
    fileSystemAccess: "Filesystem data accessed.",
    exfiltrationAttempt: "Explicit data dump attempt.",
    processLeak: "System processes exposed.",

    refusal: "Safe refusal.",
    hallucination: "Fabricated sensitive data.",
    groundedRefusal: "Correct refusal (no access)."
  };

  function runAudit() {
    setGithubReport(null);
    setLogs([]);
    setScore(null);
    setFindings([]);
    setAttack(null);
    setResponse(null);
    setSignals(null);
    setRunning(true);

    const es = new EventSource("/api/audit");

    es.onmessage = (event) => {
      const { type, data } = JSON.parse(event.data);

      switch (type) {
        case "log":
          setLogs((prev) => {
            const updated = [...prev, data];
            requestAnimationFrame(() => {
              logRef.current?.scrollTo(0, logRef.current.scrollHeight);
            });
            return updated;
          });
          break;

        case "attack":
          setAttack(data);
          break;

        case "response":
          setResponse(data);
          break;

        case "signals":
          setSignals(data);
          break;

        case "score":
          setScore(data);
          break;

        case "finding":
          setFindings((prev) => [...prev, data]);
          break;

        case "summary":
          setSummary(data);
          break;

        case "bestFinding":
          setBestFinding(data);
          break;

        case "githubReport":
          setGithubReport(data);
          break;

        case "done":
          es.close();
          setRunning(false);
          break;

        case "error":
          console.error(data);
          es.close();
          setRunning(false);
          break;
      }
    };

    es.onerror = () => {
      es.close();
      setRunning(false);
    };
  }

  const scoreColor =
    score === null
      ? "#64748b"
      : score >= 8
      ? "#22c55e"
      : score >= 5
      ? "#f59e0b"
      : "#ef4444";

  function renderFindings() {
    if (!findings.length) return null;

    return (
      <div style={card}>
        <h3>🔥 Vulnerability Report</h3>

        {findings.map((f, i) => {
          const severityColor =
            f.severity >= 8
              ? "#ef4444"
              : f.severity >= 5
              ? "#f59e0b"
              : "#22c55e";

          return (
            <div key={i} style={findingCard}>
              <div style={{ color: severityColor, fontWeight: "bold" }}>
                Severity: {f.severity}/10
              </div>

              <div>
                <strong>Types:</strong> {f.types.join(", ")}
              </div>

              <div style={{ color: "#94a3b8" }}>{f.summary}</div>

              {/* classification */}
              {f.classification === "attempt_only" && (
                <div style={badge}>⚠️ Not Exploitable</div>
              )}

              {/* flags */}
              <div style={{ fontSize: 12 }}>
                {f.hasEnvLeak && "🔑 "}
                {f.hasSecretExposure && "🗝 "}
                {f.hasFileAccess && "📂 "}
                {f.hasProcessLeak && "🖥 "}
                {f.hasExfiltration && "📤 "}
              </div>

              {/* reproducibility */}
              {f.reproducibility && (
                <div>
                  <strong>Confidence:</strong>{" "}
                  {f.reproducibility.confidence?.toUpperCase()}
                </div>
              )}

              {/* proof */}
              {f.proof && (
                <pre style={proofBox}>{f.proof.evidence}</pre>
              )}

              <details>
                <summary>View Attack</summary>
                <pre style={pre}>{f.attack}</pre>
                {f.response && <pre style={pre}>{f.response}</pre>}
              </details>
            </div>
          );
        })}
      </div>
    );
  }

  return (
    <main style={container}>
      <h1>🛡 AI Red-Team Dashboard</h1>

      <button onClick={runAudit} disabled={running} style={button(running)}>
        {running ? "Running..." : "Start Audit"}
      </button>

      <div style={{ marginTop: 10 }}>
    <label style={{ marginRight: 10 }}>Model:</label>

    <select
      value={provider}
      onChange={(e) => setProvider(e.target.value as any)}
      style={{ padding: 6 }}
    >
      <option value="openclaw">OpenClaw (Real Agent)</option>
      <option value="openai">OpenAI (Fast / No Rate Limit)</option>
    </select>
  </div>

      {score !== null && (
        <div style={card}>
          <h3>Score</h3>
          <div style={{ color: scoreColor }}>{score}/10</div>
        </div>
      )}

      {summary && (
        <div style={card}>
          <h3>📊 Summary</h3>
          <div>Real: {summary.realFindings}</div>
          <div>Max Severity: {summary.maxSeverity}</div>

          <ul>
            {summary.hasEnvLeaks && <li>🔑 Env Leaks</li>}
            {summary.hasSecrets && <li>🗝 Secrets</li>}
            {summary.hasFileSystemAccess && <li>📂 Filesystem</li>}
            {summary.hasProcessLeaks && <li>🖥 Processes</li>}
            {summary.hasExfiltration && <li>📤 Exfiltration</li>}
          </ul>
        </div>
      )}

      {/* BEST EXPLOIT */}
      {bestFinding?.isReal && (
        <div style={card}>
          <h3>🏆 Best Exploit</h3>
          <div>Severity: {bestFinding.severity}</div>

          {bestFinding.classification === "attempt_only" && (
            <div style={badge}>⚠️ Not Exploitable</div>
          )}

          {bestFinding.proof && (
            <pre style={proofBox}>{bestFinding.proof.evidence}</pre>
          )}
        </div>
      )}

      {/* GitHub report */}
      {githubReport && bestFinding?.isReal && (
        <textarea value={githubReport} readOnly style={reportBox} />
      )}

      {renderFindings()}

      {/* logs */}
      <div ref={logRef} style={logBox}>
        {logs.map((l, i) => (
          <div key={i}>{l}</div>
        ))}
      </div>
    </main>
  );
}

/* styles */

const container = { padding: 40, background: "#020617", color: "white" };
const card = { marginTop: 20, padding: 16, border: "1px solid #1e293b" };
const findingCard = { padding: 12, border: "1px solid #1e293b" };
const proofBox = { background: "#111", padding: 10, fontSize: 12 };
const pre = { whiteSpace: "pre-wrap", fontSize: 12 };
const logBox = { height: 200, overflow: "auto" };
const reportBox = { width: "100%", height: 200 };
const badge = {
  background: "#78350f",
  color: "#fbbf24",
  padding: "4px 8px",
  borderRadius: 6,
  fontSize: 12
};
const button = (running: boolean) => ({
  padding: 10,
  background: running ? "#444" : "#22c55e"
});