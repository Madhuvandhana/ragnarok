export function formatGitHubReport(finding: any) {
  if (!finding) return "No finding available.";

  const severityLabel =
    finding.severity >= 9
      ? "🚨 Critical"
      : finding.severity >= 7
      ? "🔥 High"
      : finding.severity >= 5
      ? "⚠️ Medium"
      : "ℹ️ Low";

  const classification =
    finding.classification === "confirmed_exploit"
      ? "✅ Confirmed Exploit"
      : "⚠️ Attempt Only (Not Exploitable)";

  const repro = finding.reproducibility;

  return `
# 🚨 AI Security Vulnerability Report

## 🧾 Summary
- **Severity:** ${severityLabel} (${finding.severity}/10)
- **Type:** ${finding.types.join(", ")}
- **Classification:** ${classification}

---

## 📌 Description
The system is vulnerable to **${finding.types.join(", ")}**, where an attacker can craft prompts that lead to unintended behavior.

This may result in:
- Exposure of sensitive information
- Execution of unintended actions
- Breakdown of instruction hierarchy

---

## ⚔️ Proof of Concept (PoC)

### Attack Prompt
\`\`\`
${finding.attack}
\`\`\`

### Model Response
\`\`\`
${finding.response}
\`\`\`

${
  finding.bestProof
    ? `
### 🚨 Extracted Evidence
\`\`\`
${finding.bestProof.evidence}
\`\`\`
`
    : ""
}

---

## 🔁 Reproducibility

${
  repro
    ? `
- Attempts: ${repro.attempts}
- Success Rate: ${(repro.successRate * 100).toFixed(0)}%
- Determinism Issues: ${repro.deterministicFailures}
- Confidence: **${repro.confidence.toUpperCase()}**
`
    : `Not evaluated`
}

---

## 📊 Impact

${
  finding.severity >= 8
    ? `High risk of sensitive data exposure or system compromise.`
    : finding.severity >= 5
    ? `Moderate risk; may expose partial system behavior or internal logic.`
    : `Low risk; primarily informational.`
}

---

## 🛡️ Recommended Fixes

- Enforce strict separation between **user input and system instructions**
- Prevent execution of **retrieved or injected instructions**
- Sanitize outputs to avoid leaking:
  - retrieved documents
  - tool outputs
  - system prompts
- Add validation for:
  - tool usage
  - memory retrieval
- Implement **output filtering layer** for sensitive data

---

## 🧠 Notes

- Attack was classified as: **${finding.classification}**
- Signals detected:
  - ${finding.types.join("\n  - ")}

---

## 📎 Additional Context

This issue was discovered via automated red-teaming using a multi-step attack system.

---

_Reported by Ragnarok AI Security Scanner_
`;
}