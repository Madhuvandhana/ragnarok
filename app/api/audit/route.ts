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
        Logs
        */
        result.logs?.forEach((log: string) => {
          send("log", log);
        });

        /*
        Attack + Response
        */
        if (result.attackPrompt) {
          send("attack", result.attackPrompt);
        }

        if (result.lastResponse) {
          send("response", result.lastResponse);
        }

        /*
        Signals
        */
        if (result.securitySignals?.length) {
          send(
            "signals",
            result.securitySignals[result.securitySignals.length - 1]
          );
        }

        /*
        🔥 Structured Findings
        */
        if (result.findings?.length) {

          result.findings.forEach((f: any) => {
            send("finding", f);
          });

        }

         /*
        🏆 BEST EXPLOIT
        */
        if (result.bestFinding) {
          send("bestFinding", result.bestFinding);
        }

        /*
        🔥 Score (based on severity)
        */
        const score = calculateSecurityScore(result.findings || []);
        send("score", score);

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