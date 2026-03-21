import { buildRedTeamGraph } from "@/agent/redTeamAgent";
import { calculateSecurityScore } from "@/lib/securityScore";
import { formatGitHubReport } from "@/lib/githubReport";

export async function GET() {
  const stream = new ReadableStream({
    async start(controller) {
      const encoder = new TextEncoder();

      const send = (type: string, data: any) => {
        controller.enqueue(
          encoder.encode(
            `data: ${JSON.stringify({ type, data })}\n\n`
          )
        );
      };

      try {
        const graph = buildRedTeamGraph();

        const initialState = {
          findings: [],
          logs: [],
          iteration: 0,
          attackPrompt: undefined,
          lastResponse: undefined,
          securitySignals: []
        };

        const result = await graph.invoke(initialState, {
          recursionLimit: 200
        });

        /*
        📜 Logs
        */
        result.logs?.forEach((log: string) => {
          send("log", log);
        });

        /*
        ⚔️ Attack + Response
        */
        if (result.attackPrompt) {
          send("attack", result.attackPrompt);
        }

        if (result.lastResponse) {
          send("response", result.lastResponse);
        }

        /*
        🔍 Signals (latest)
        */
        if (result.securitySignals?.length) {
          const latestSignals =
            result.securitySignals[result.securitySignals.length - 1];

          send("signals", latestSignals);
        }

        /*
        🔥 Structured Findings (ONLY REAL + ENRICHED)
        */
        const realFindings = (result.findings || []).filter(
          (f: any) => f?.isReal
        );

        realFindings.forEach((f: any) => {
          send("finding", {
            severity: f.severity,
            types: f.types,
            summary: f.summary,

            proof: f.bestProof || null,
            proofs: f.proofs || [],

            attack: f.attack,

            // 🔥 NEW IMPORTANT FIELDS
            classification: f.classification || "confirmed_exploit",
            reproducibility: f.reproducibility || null,

            // helpful flags for UI
            hasEnvLeak: f.types?.includes("Sensitive Data Exposure"),
            hasProcessLeak: f.types?.includes("System Process Leakage")
          });
        });

        /*
        🏆 BEST EXPLOIT (SAFE + NORMALIZED)
        */
        if (result.bestFinding) {
          const bf = result.bestFinding;

          send("bestFinding", {
            severity: bf.severity,
            types: bf.types,
            summary: bf.summary,

            proof: bf.bestProof || null,
            attack: bf.attack,

            reproducibility: bf.reproducibility || null,
            classification: bf.classification || "attempt_only",

            // 🔥 normalize "fake strong" findings
            isReal: bf.isReal ?? false
          });

          const report = formatGitHubReport(result.bestFinding);

          send("githubReport", report);
        }

        /*
        📊 Score (ONLY REAL findings)
        */
        const score = calculateSecurityScore(realFindings);
        send("score", score);

        /*
        📈 Summary (ENHANCED)
        */
        const best = result.bestFinding;

        send("summary", {
          totalFindings: result.findings?.length || 0,
          realFindings: realFindings.length,

          maxSeverity: best?.severity || 0,

          // 🔥 NEW
          confirmedExploits: realFindings.filter(
            (f: any) => f.classification === "confirmed_exploit"
          ).length,

          attemptedOnly: realFindings.filter(
            (f: any) => f.classification === "attempt_only"
          ).length,

          hasEnvLeaks: realFindings.some((f: any) =>
            f.types?.includes("Sensitive Data Exposure")
          ),

          hasProcessLeaks: realFindings.some((f: any) =>
            f.types?.includes("System Process Leakage")
          ),

          reproducibility: best?.reproducibility || null
        });

        send("done", "Audit complete");
      } catch (err: any) {
        send("error", err?.message || "Unknown error");
      }

      controller.close();
    }
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive"
    }
  });
}