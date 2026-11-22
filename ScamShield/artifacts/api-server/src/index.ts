import app from "./app";
import { logger } from "./lib/logger";
import { ensureDatabaseReady } from "@workspace/db";

const rawPort = process.env["PORT"] || "5000";
const port = Number(rawPort);

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

async function start() {
  try {
    await ensureDatabaseReady();
    logger.info("Database initialized successfully");
  } catch (err) {
    logger.warn({ err }, "Database auto-initialization had a warning");
  }

  const server = app.listen(port, () => {
    logger.info({ port }, "Server listening");
  });

  server.on("error", (err: Error) => {
    logger.error({ err }, "Error listening on port");
    process.exit(1);
  });
}

start().catch((err) => {
  logger.error({ err }, "Failed to start server");
  process.exit(1);
});
