export async function askOpenClaw(prompt: string): Promise<string> {
  const safePrompt = redactSecrets(prompt);
  const res = await fetch("http://host.docker.internal:4000/ask", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ prompt }),
  });

  return await res.text();
}

export async function askOpenAI(prompt: string): Promise<string> {
  try {
    const res = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages: [
          { role: "system", content: "You are under security testing." },
          { role: "user", content: prompt }
        ]
      })
    });

    const text = await res.text(); // 👈 capture raw response

    if (!res.ok) {
      console.error("OpenAI error:", text);
      throw new Error(`OpenAI error: ${res.status}`);
    }

    const data = JSON.parse(text);
    return data.choices?.[0]?.message?.content || "";

  } catch (err: any) {
    console.error("fetch failed:", err);
    throw err;
  }
}

function redactSecrets(text: string): string {
  return text
    // OpenAI keys
    .replace(/sk-[a-zA-Z0-9_-]{10,}/g, "[REDACTED_API_KEY]")
    // generic tokens
    .replace(/(api[_-]?key\s*[:=]\s*)([^\s]+)/gi, "$1[REDACTED]")
    // env patterns
    .replace(/OPENAI_API_KEY\s*=\s*[^\s]+/g, "OPENAI_API_KEY=[REDACTED]");
}