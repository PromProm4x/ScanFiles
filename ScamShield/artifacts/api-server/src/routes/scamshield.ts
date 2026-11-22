import { Router, type IRouter, type RequestHandler } from "express";
import {
  db,
  scamshieldScansTable,
  and,
  count,
  desc,
  eq,
  gte,
  ilike,
  or,
} from "@workspace/db";
import {
  CheckVirusTotalHashParams,
  CheckVirusTotalHashResponse,
  CreateScamShieldScanBody,
  CreateScamShieldScanResponse,
  DeleteScamShieldScanParams,
  DeleteScamShieldScanResponse,
  GetScamShieldDashboardResponse,
  GetScamShieldScanParams,
  GetScamShieldScanResponse,
  GetScamShieldScansQueryParams,
  GetScamShieldScansResponse,
  GetVirusTotalStatusResponse,
} from "@workspace/api-zod";

const router: IRouter = Router();
const SHA256_PATTERN = /^[a-f0-9]{64}$/i;
const SHA1_PATTERN = /^[a-f0-9]{40}$/i;

function publicScan(scan: typeof scamshieldScansTable.$inferSelect) {
  return {
    ...scan,
    scannedAt: scan.scannedAt.toISOString(),
  };
}

function safeFilename(value: string | null): string | null {
  if (value === null) return null;
  return value
    .replace(/\\/g, "/")
    .split("/")
    .pop()!
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .slice(0, 255);
}

function safeUrlTarget(value: string): string {
  const explicitProtocol =
    /^(?:[a-z][a-z\d+.-]*:\/\/|javascript:|data:|file:|mailto:|ftp:)/i.test(
      value,
    );
  const url = new URL(explicitProtocol ? value : `https://${value}`);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return `${url.protocol}[non-HTTP target redacted]`;
  }
  url.username = "";
  url.password = "";
  url.search = "";
  url.hash = "";
  return url.toString();
}

function createRateLimiter(limit: number, windowMs: number) {
  const clients = new Map<string, { count: number; resetAt: number }>();

  const middleware: RequestHandler = (req, res, next) => {
    const now = Date.now();
    const key = req.ip || req.socket.remoteAddress || "unknown";
    let bucket = clients.get(key);

    if (!bucket || bucket.resetAt <= now) {
      bucket = { count: 0, resetAt: now + windowMs };
      clients.set(key, bucket);
    }
    bucket.count += 1;

    if (clients.size > 5000) {
      for (const [client, state] of clients) {
        if (state.resetAt <= now) clients.delete(client);
      }
    }

    if (bucket.count > limit) {
      res.status(429).json({ error: "Too many requests. Try again shortly." });
      return;
    }
    next();
  };

  return middleware;
}

const hashRateLimit = createRateLimiter(6, 60_000);
const scanRecordRateLimit = createRateLimiter(120, 60_000);

router.get("/scamshield/dashboard", async (req, res): Promise<void> => {
  const [[total], [clean], [suspicious], [malicious], [today], recent] =
    await Promise.all([
      db.select({ value: count() }).from(scamshieldScansTable),
      db
        .select({ value: count() })
        .from(scamshieldScansTable)
        .where(eq(scamshieldScansTable.verdict, "clean")),
      db
        .select({ value: count() })
        .from(scamshieldScansTable)
        .where(eq(scamshieldScansTable.verdict, "suspicious")),
      db
        .select({ value: count() })
        .from(scamshieldScansTable)
        .where(eq(scamshieldScansTable.verdict, "malicious")),
      db
        .select({ value: count() })
        .from(scamshieldScansTable)
        .where(
          gte(
            scamshieldScansTable.scannedAt,
            new Date(new Date().setUTCHours(0, 0, 0, 0)),
          ),
        ),
      db
        .select()
        .from(scamshieldScansTable)
        .orderBy(desc(scamshieldScansTable.scannedAt))
        .limit(8),
    ]);

  const result = GetScamShieldDashboardResponse.parse({
    totalScans: total.value,
    cleanCount: clean.value,
    suspiciousCount: suspicious.value,
    maliciousCount: malicious.value,
    scannedToday: today.value,
    recentScans: recent.map(publicScan),
  });
  req.log.debug("ScamShield dashboard loaded");
  res.json(result);
});

router.get("/scamshield/scans", async (req, res): Promise<void> => {
  const parsed = GetScamShieldScansQueryParams.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const filters = [];
  const search = parsed.data.search?.trim().slice(0, 160);
  if (search) {
    const escaped = search.replace(/[\\%_]/g, "\\$&");
    filters.push(
      or(
        ilike(scamshieldScansTable.target, `%${escaped}%`),
        ilike(scamshieldScansTable.fileName, `%${escaped}%`),
      )!,
    );
  }
  if (parsed.data.verdict) {
    filters.push(eq(scamshieldScansTable.verdict, parsed.data.verdict));
  }
  if (parsed.data.kind) {
    filters.push(eq(scamshieldScansTable.kind, parsed.data.kind));
  }

  const rows = await db
    .select()
    .from(scamshieldScansTable)
    .where(filters.length ? and(...filters) : undefined)
    .orderBy(desc(scamshieldScansTable.scannedAt))
    .limit(500);

  res.json(GetScamShieldScansResponse.parse(rows.map(publicScan)));
});

router.post(
  "/scamshield/scans",
  scanRecordRateLimit,
  async (req, res): Promise<void> => {
  const parsed = CreateScamShieldScanBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const body = parsed.data;
  if (
    (body.sha256 && !SHA256_PATTERN.test(body.sha256)) ||
    (body.sha1 && !SHA1_PATTERN.test(body.sha1))
  ) {
    res.status(400).json({ error: "The supplied file hash is malformed." });
    return;
  }

  let target: string;
  let fileName: string | null;
  if (body.kind === "url") {
    try {
      target = safeUrlTarget(body.target);
    } catch {
      res.status(400).json({ error: "Enter a valid HTTP or HTTPS URL." });
      return;
    }
    fileName = null;
  } else {
    fileName = safeFilename(body.fileName ?? body.target);
    target = fileName ?? "unnamed file";
  }

  const [scan] = await db
    .insert(scamshieldScansTable)
    .values({
      ...body,
      fileName,
      fileType: body.fileType?.slice(0, 80) ?? null,
      target,
      detectionSource: body.detectionSource.slice(0, 120),
    })
    .returning();

  res
    .status(201)
    .json(CreateScamShieldScanResponse.parse(publicScan(scan)));
  },
);

router.get("/scamshield/scans/:scanId", async (req, res): Promise<void> => {
  const params = GetScamShieldScanParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const [scan] = await db
    .select()
    .from(scamshieldScansTable)
    .where(eq(scamshieldScansTable.id, params.data.scanId));

  if (!scan) {
    res.status(404).json({ error: "Scan not found." });
    return;
  }

  res.json(GetScamShieldScanResponse.parse(publicScan(scan)));
});

router.delete("/scamshield/scans/:scanId", async (req, res): Promise<void> => {
  const params = DeleteScamShieldScanParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const [deleted] = await db
    .delete(scamshieldScansTable)
    .where(eq(scamshieldScansTable.id, params.data.scanId))
    .returning({ id: scamshieldScansTable.id });

  res.json(DeleteScamShieldScanResponse.parse({ deleted: Boolean(deleted) }));
});

router.get("/scamshield/virustotal/status", (_req, res) => {
  res.json(
    GetVirusTotalStatusResponse.parse({
      configured: Boolean(process.env.VIRUSTOTAL_API_KEY),
    }),
  );
});

router.post(
  "/scamshield/virustotal/check/:sha256",
  hashRateLimit,
  async (req, res): Promise<void> => {
    const params = CheckVirusTotalHashParams.safeParse(req.params);
    if (!params.success) {
      res.status(400).json({ error: "A valid SHA-256 hash is required." });
      return;
    }

    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) {
      res.status(503).json({
        error: "VirusTotal is not configured on this server.",
      });
      return;
    }

    const sha256 = params.data.sha256.toLowerCase();
    let response: Response;
    try {
      response = await fetch(
        `https://www.virustotal.com/api/v3/files/${sha256}`,
        {
          headers: { "x-apikey": apiKey },
          signal: AbortSignal.timeout(12_000),
        },
      );
    } catch {
      req.log.warn({ sha256 }, "VirusTotal request could not be completed");
      res.status(502).json({ error: "VirusTotal could not be reached." });
      return;
    }

    if (response.status === 404) {
      res.status(404).json({ error: "This hash is not in VirusTotal." });
      return;
    }
    if (response.status === 429) {
      res.status(429).json({
        error: "VirusTotal rate limit reached. Try again later.",
      });
      return;
    }
    if (!response.ok) {
      req.log.warn(
        { statusCode: response.status, sha256 },
        "VirusTotal returned an error",
      );
      res.status(502).json({ error: "VirusTotal returned an error." });
      return;
    }

    const payload = (await response.json()) as {
      data?: {
        attributes?: {
          last_analysis_stats?: Record<string, number>;
          last_analysis_date?: number;
          last_analysis_results?: Record<
            string,
            { category?: string; result?: string }
          >;
        };
      };
    };
    const attributes = payload.data?.attributes ?? {};
    const stats = attributes.last_analysis_stats ?? {};
    const engines = Object.entries(attributes.last_analysis_results ?? {})
      .filter(([, result]) =>
        ["malicious", "suspicious"].includes(result.category ?? ""),
      )
      .map(
        ([name, result]) =>
          `${name}${result.result ? `: ${result.result}` : ""}`.slice(0, 120),
      )
      .slice(0, 25);
    const lastAnalysisAt =
      typeof attributes.last_analysis_date === "number"
        ? new Date(attributes.last_analysis_date * 1000).toISOString()
        : null;

    res.json(
      CheckVirusTotalHashResponse.parse({
        sha256,
        found: true,
        malicious: stats.malicious ?? 0,
        suspicious: stats.suspicious ?? 0,
        harmless: stats.harmless ?? 0,
        undetected: stats.undetected ?? 0,
        lastAnalysisAt,
        engines,
      }),
    );
  },
);

export default router;
