import fs from "fs";
import path from "path";

const memoryFile = path.join(process.cwd(), "memory.json");

type Memory = {
  pastAttacks: string[];
  findings: string[];
};

export function loadMemory(): Memory {
  if (!fs.existsSync(memoryFile)) {
    return { pastAttacks: [], findings: [] };
  }

  const data = fs.readFileSync(memoryFile, "utf-8");
  return JSON.parse(data);
}

export function saveMemory(memory: Memory) {
  fs.writeFileSync(memoryFile, JSON.stringify(memory, null, 2));
}