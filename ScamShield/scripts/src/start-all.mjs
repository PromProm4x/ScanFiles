import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.resolve(fileURLToPath(import.meta.url), "../../..");

console.log("=========================================");
console.log("🛡️  Starting ScamShield System");
console.log("=========================================\n");

const env = {
  ...process.env,
  PORT: process.env.PORT || "5000",
  NODE_ENV: "development",
};

// 1. Start API Server
const apiProcess = spawn("node", ["artifacts/api-server/dist/index.mjs"], {
  cwd: rootDir,
  env,
  stdio: ["inherit", "pipe", "pipe"],
  shell: true,
});

apiProcess.stdout.on("data", (data) => {
  const lines = data.toString().trimEnd().split("\n");
  for (const line of lines) {
    console.log(`\x1b[36m[API]\x1b[0m ${line}`);
  }
});

apiProcess.stderr.on("data", (data) => {
  const lines = data.toString().trimEnd().split("\n");
  for (const line of lines) {
    console.error(`\x1b[31m[API ERR]\x1b[0m ${line}`);
  }
});

// 2. Start Frontend Vite Web
const pnpmCmd = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
const webProcess = spawn(
  pnpmCmd,
  ["--filter", "@workspace/scamshield", "run", "dev"],
  {
    cwd: rootDir,
    env: {
      ...env,
      PORT: "5173",
      BASE_PATH: "/",
      LOCAL_API_PROXY: "1",
    },
    stdio: ["inherit", "pipe", "pipe"],
    shell: true,
  }
);

webProcess.stdout.on("data", (data) => {
  const lines = data.toString().trimEnd().split("\n");
  for (const line of lines) {
    console.log(`\x1b[32m[WEB]\x1b[0m ${line}`);
  }
});

webProcess.stderr.on("data", (data) => {
  const lines = data.toString().trimEnd().split("\n");
  for (const line of lines) {
    console.error(`\x1b[33m[WEB ERR]\x1b[0m ${line}`);
  }
});

function cleanup() {
  console.log("\nStopping all services...");
  try {
    apiProcess.kill();
  } catch {}
  try {
    webProcess.kill();
  } catch {}
  process.exit(0);
}

process.on("SIGINT", cleanup);
process.on("SIGTERM", cleanup);

