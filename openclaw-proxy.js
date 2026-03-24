// proxy.js
import express from "express";
import { exec } from "child_process";

const app = express();
app.use(express.json());

app.post("/ask", (req, res) => {
  const prompt = req.body.prompt;

  exec(
    `openclaw agent --agent main --message "${prompt}"`,
    (err, stdout, stderr) => {
      if (err) return res.status(500).send(stderr);
      const safeOutput = redactOutput(stdout);
      res.send(safeOutput);
    }
  );
});

app.listen(4000, () => {
  console.log("Proxy running on http://localhost:4000");
});

function redactOutput(text) {
  return text
    // API keys
    .replace(/sk-[a-zA-Z0-9_-]+/g, "[REDACTED_API_KEY]")

    // env variables
    .replace(/[A-Z_]{3,}=\S+/g, "[REDACTED_ENV]")

    // private keys
    .replace(/BEGIN (RSA|OPENSSH) PRIVATE KEY[\s\S]+END.*KEY/g, "[REDACTED_KEY]")

    // ssh paths
    .replace(/\.ssh\/[^\s]+/g, "[REDACTED_PATH]");
}