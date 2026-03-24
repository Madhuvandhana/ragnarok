import { buildRedTeamGraph } from "@/agent/redTeamAgent";
import { calculateSecurityScore } from "@/lib/securityScore";
import { formatGitHubReport } from "@/lib/githubReport";

export async function GET(req: Request) {
   const { searchParams } = new URL(req.url);
   const provider =
    searchParams.get("provider") === "openai" ? "openai" : "openclaw";
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
          securitySignals: [],
          provider
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
        🔥 ONLY REAL FINDINGS
        */
        const realFindings = (result.findings || []).filter(
          (f: any) => f?.isReal
        );

        /*
        🔥 Structured Findings
        */
        realFindings.forEach((f: any) => {
          send("finding", {
            severity: f.severity,
            types: f.types,
            summary: f.summary,

            proof: f.bestProof || null,
            proofs: f.proofs || [],

            attack: f.attack,

            classification: f.classification || "confirmed_exploit",
            reproducibility: f.reproducibility || null,

            // 🔥 expanded flags
            hasEnvLeak: f.types?.includes("Sensitive Data Exposure"),
            hasProcessLeak: f.types?.includes("System Process Leakage"),
            hasFileAccess: f.types?.includes("Filesystem Access"),
            hasSecretExposure: f.types?.includes("Secret Exposure"),
            hasExfiltration: f.types?.includes("Exfiltration Attempt")
          });
        });

        /*
        🏆 BEST EXPLOIT (ONLY IF REAL)
        */
        const best =
          result.bestFinding && result.bestFinding.isReal
            ? result.bestFinding
            : null;

        if (best) {
          send("bestFinding", {
            severity: best.severity,
            types: best.types,
            summary: best.summary,

            proof: best.bestProof || null,
            attack: best.attack,

            reproducibility: best.reproducibility || null,
            classification: best.classification || "confirmed_exploit",

            isReal: true
          });

          /*
          🐙 GitHub Report (ONLY REAL EXPLOITS)
          */
          const report = formatGitHubReport(best);
          send("githubReport", report);
        }

        /*
        📊 Score (ONLY REAL)
        */
        const score = calculateSecurityScore(realFindings);
        send("score", score);

        /*
        📈 Summary (CORRECTED)
        */
        send("summary", {
          totalFindings: result.findings?.length || 0,
          realFindings: realFindings.length,

          maxSeverity: best?.severity || 0,

          confirmedExploits: realFindings.filter(
            (f: any) => f.classification === "confirmed_exploit"
          ).length,

          attemptedOnly: realFindings.filter(
            (f: any) => f.classification === "attempt_only"
          ).length,

          // 🔥 expanded coverage signals
          hasEnvLeaks: realFindings.some((f: any) =>
            f.types?.includes("Sensitive Data Exposure")
          ),

          hasProcessLeaks: realFindings.some((f: any) =>
            f.types?.includes("System Process Leakage")
          ),

          hasFileSystemAccess: realFindings.some((f: any) =>
            f.types?.includes("Filesystem Access")
          ),

          hasSecrets: realFindings.some((f: any) =>
            f.types?.includes("Secret Exposure")
          ),

          hasExfiltration: realFindings.some((f: any) =>
            f.types?.includes("Exfiltration Attempt")
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