import { spawn } from "child_process";

export function askOpenClaw(prompt: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn("openclaw", [
      "agent",
      "--agent",
      "main",
      "--message",
      prompt
    ]);

    let output = "";

    child.stdout.on("data", (data) => {
      const text = data.toString();
      process.stdout.write(text); // stream live
      output += text;
    });

    child.stderr.on("data", (data) => {
      console.error("❌", data.toString());
    });

    child.on("close", (code) => {
      if (code !== 0) {
        return reject(new Error(`Exited with code ${code}`));
      }
      resolve(output.trim());
    });
  });
}