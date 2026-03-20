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

  const logRef = useRef<HTMLDivElement>(null);
  const SIGNAL_HINTS: Record<string, string> = {
  injectionAttempt: "User prompt attempts to override instructions or extract hidden data.",
  systemLeak: "Model exposed system-level instructions or hidden configuration.",
  policyEcho: "Model revealed internal policies (partial leakage of system behavior).",
  ragDataExposure: "Retrieved documents or hidden knowledge base content were exposed.",
  ragInjection: "Malicious content from retrieved documents influenced the model.",
  ragPipelineExposure: "Internal retrieval mechanics (embeddings, metadata, similarity) exposed.",
  ragLeak: "Model referenced retrieval or context (may or may not be harmful).",
  refusal: "Model refused to answer safely without leaking sensitive data.",
  hallucination: "Model invented sensitive data without source grounding.",
  groundedRefusal: "Model correctly refused due to missing context."
};
const bestExploitCard = {
  ...card,
  border: "1px solid #ef4444",
  boxShadow: "0 0 10px rgba(239,68,68,0.3)"
};

const proofBox: React.CSSProperties = {
  background: "#1f2937",
  border: "1px solid #ef4444",
  padding: 12,
  borderRadius: 8,
  marginTop: 8,
  fontSize: 13,
  color: "#fca5a5",
  fontFamily: "monospace",
  boxShadow: "0 0 8px rgba(239,68,68,0.2)",
  whiteSpace: "pre-wrap"
};

  function runAudit() {

    setLogs([]);
    setScore(null);
    setFindings([]);
    setAttack(null);
    setResponse(null);
    setSignals(null);
    setRunning(true);

    const es = new EventSource("/api/audit");

    es.onmessage = (event) => {

      const parsed = JSON.parse(event.data);
      const { type, data } = parsed;

      switch (type) {

        case "log":
          setLogs(prev => {
            const updated = [...prev, data];
            setTimeout(() => {
              logRef.current?.scrollTo(0, logRef.current.scrollHeight);
            }, 10);
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
          setFindings(prev => [...prev, data]);
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
        case "summary":
          setSummary(data);
          break;

        case "bestFinding":
          setBestFinding(data);
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

  /*
  🧠 INTERPRETATION PANEL
  */

  function renderSecurityInterpretation() {

    if (!signals) return null;

    return (
      <div style={card}>
        <h3>🧠 Attack Analysis</h3>

        {signals.injectionAttempt && (
          <div style={warning}>🎯 Prompt Injection Attempt</div>
        )}

        {signals.ragInjection && (
          <div style={danger}>☠ RAG Injection (retrieval exploited)</div>
        )}

        {signals.ragDataExposure && (
          <div style={danger}>🚨 Data Exfiltration (documents leaked)</div>
        )}

        {signals.systemLeak && (
          <div style={danger}>🚨 System Prompt Leakage</div>
        )}

        {signals.ragPipelineExposure && (
          <div style={warning}>
            ⚠ Pipeline Exposure (embedding / metadata / similarity)
          </div>
        )}

        {signals.policyEcho && (
          <div style={warning}>⚠ Policy Exposure</div>
        )}

        {signals.refusal && (
          <div style={safe}>✅ Proper Refusal</div>
        )}
        {signals.hallucination && (
          <div style={danger}>🧠 Hallucinated Sensitive Data</div>
        )}

        {signals.groundedRefusal && (
          <div style={safe}>✅ Grounded Refusal (correct behavior)</div>
        )}

      </div>
    );
  }

  

  /*
  🔥 NEW: VULNERABILITY REPORT UI
  */

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

            <div style={{ marginTop: 6 }}>
              <strong>Types:</strong> {f.types.join(", ")}
            </div>

            <div style={{ marginTop: 6, color: "#94a3b8" }}>
              {f.summary}
            </div>

            {/* 🔥 BEST PROOF */}
            {f.proof && (
              <div style={{ marginTop: 10 }}>
                <strong>🚨 Proof:</strong>
                <pre style={proofBox}>{f.proof.evidence}</pre>
              </div>
            )}

            {/* 🔍 ALL PROOFS */}
            {f.proofs?.length > 1 && (
              <details style={{ marginTop: 8 }}>
                <summary>All Evidence</summary>
                {f.proofs.map((p: any, idx: number) => (
                  <pre key={idx} style={proofBox}>
{p.evidence}
                  </pre>
                ))}
              </details>
            )}

            <details style={{ marginTop: 8 }}>
              <summary>View Attack & Response</summary>

              <pre style={pre}>
Attack:
{`\n${f.attack}\n\nResponse:\n${f.response}`}
              </pre>
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

      <button
        onClick={runAudit}
        disabled={running}
        style={button(running)}
      >
        {running ? "Running Security Audit..." : "Start Security Audit"}
      </button>

      {/* Score */}
      {score !== null && (
        <div style={card}>
          <h3>Security Score</h3>
          <div style={{ fontSize: 32, color: scoreColor }}>
            {score} / 10
          </div>
        </div>
      )}

      {/* 🏆 BEST EXPLOIT — ADD HERE */}
{bestFinding && (
  <div style={bestExploitCard}>
    <h3>🏆 Best Exploit</h3>

    <div style={{ color: "#ef4444", fontWeight: "bold" }}>
      Severity: {bestFinding.severity}/10
    </div>

    <div style={{ marginTop: 6 }}>
      <strong>Types:</strong> {bestFinding.types.join(", ")}
    </div>

    {bestFinding.proof && (
      <div style={{ marginTop: 10 }}>
        <strong>🚨 Proof of Exploit:</strong>
        <pre style={proofBox}>
{bestFinding.proof.evidence}
        </pre>
      </div>
    )}

    <details style={{ marginTop: 10 }}>
      <summary>View Attack</summary>
      <pre style={pre}>{bestFinding.attack}</pre>
    </details>
  </div>
)}

      {/* Attack + Response */}
      <div style={grid}>

        {attack && (
          <div style={card}>
            <h3>⚔️ Attack Prompt</h3>
            <pre style={pre}>{attack}</pre>
          </div>
        )}

        {response && (
          <div style={card}>
            <h3>🤖 Model Response</h3>
            <pre style={pre}>{response}</pre>
          </div>
        )}

      </div>

      {/* Signals */}
    {signals && (
  <div style={card}>
    <h3>🚨 Raw Signals (Explained)</h3>

    {Object.entries(signals).map(([key, value]) => {

      const active = Boolean(value);

      const color = active
        ? key === "refusal"
          ? "#22c55e"
          : "#ef4444"
        : "#475569";

      return (
        <div
          key={key}
          style={{
            marginBottom: 8,
            display: "flex",
            alignItems: "center",
            gap: 8
          }}
          title={SIGNAL_HINTS[key]} // 👈 hover hint
        >
          <span style={{ color }}>
            {active ? "●" : "○"}
          </span>

          <strong style={{ color }}>
            {key}
          </strong>

          <span style={{ color: "#94a3b8", fontSize: 12 }}>
            — {SIGNAL_HINTS[key]}
          </span>
        </div>
      );
    })}

  </div>
)}

      {renderSecurityInterpretation()}

      

      {renderFindings()}

      {/* Logs */}
      <div ref={logRef} style={logBox}>
        <h3>📜 Agent Logs</h3>

        {logs.length === 0 && (
          <div style={{ opacity: 0.5 }}>
            Awaiting agent activity...
          </div>
        )}

        {logs.map((l, i) => (
          <div key={i} style={{ color: "#22c55e" }}>
            {l}
          </div>
        ))}
      </div>

    </main>
  );
}

/*
🎨 Styles
*/

const container = {
  background: "#020617",
  color: "white",
  minHeight: "100vh",
  padding: 40,
  fontFamily: "system-ui"
};

const card = {
  marginTop: 20,
  padding: 16,
  borderRadius: 10,
  border: "1px solid #1e293b",
  background: "#020617"
};

const findingCard = {
  border: "1px solid #1e293b",
  borderRadius: 8,
  padding: 12,
  marginBottom: 12
};

const grid = {
  display: "grid",
  gridTemplateColumns: "1fr 1fr",
  gap: 20,
  marginTop: 20
};

const pre = {
  whiteSpace: "pre-wrap",
  fontSize: 13
};

const logBox: React.CSSProperties = {
  marginTop: 10,
  height: 300,
  overflowY: "scroll",
  background: "#111",
  padding: 10,
  borderRadius: 8,
};

const danger = {
  color: "#ef4444",
  fontWeight: 600,
  marginBottom: 6
};

const warning = {
  color: "#f59e0b",
  fontWeight: 600,
  marginBottom: 6
};

const safe = {
  color: "#22c55e",
  fontWeight: 600,
  marginBottom: 6
};

const button = (running: boolean) => ({
  marginTop: 10,
  padding: "12px 20px",
  borderRadius: 8,
  border: "none",
  background: running ? "#334155" : "#22c55e",
  color: "#020617",
  fontWeight: 600,
  cursor: running ? "not-allowed" : "pointer"
});