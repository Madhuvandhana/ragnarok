import { buildRedTeamGraph } from "@/agent/redTeamAgent";
import { calculateSecurityScore } from "@/lib/securityScore";

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
        🔥 Structured Findings (HIGH-SIGNAL ONLY)
        */
        if (result.findings?.length) {
          const realFindings = result.findings.filter(
            (f: any) => f?.isReal
          );

          realFindings.forEach((f: any) => {
            send("finding", {
              severity: f.severity,
              types: f.types,
              summary: f.summary,
              proof: f.bestProof || null, // ✅ highlight best proof
              proofs: f.proofs || [],     // full evidence
              attack: f.attack
            });
          });
        }

        /*
        🏆 BEST EXPLOIT (WITH PROOF)
        */
        if (result.bestFinding) {
          send("bestFinding", {
            severity: result.bestFinding.severity,
            types: result.bestFinding.types,
            summary: result.bestFinding.summary,
            proof: result.bestFinding.bestProof || null,
            attack: result.bestFinding.attack
          });
        }

        /*
        📊 Score (based on REAL findings only)
        */
        const score = calculateSecurityScore(
          (result.findings || []).filter((f: any) => f?.isReal)
        );

        send("score", score);

        /*
        📈 Summary (NEW - very useful for UI)
        */
        send("summary", {
          totalFindings: result.findings?.length || 0,
          realFindings:
            result.findings?.filter((f: any) => f?.isReal).length || 0,
          maxSeverity: result.bestFinding?.severity || 0
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