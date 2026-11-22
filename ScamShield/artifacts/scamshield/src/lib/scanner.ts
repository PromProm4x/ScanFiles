import { createSHA1, createSHA256 } from "hash-wasm";

export const DEFAULT_MAX_SCAN_MB = 1024;
export const HASH_CHUNK_SIZE_BYTES = 4 * 1024 * 1024;

export type LocalAnalysis = {
  fileType: string;
  sha256: string | null;
  sha1: string | null;
  indicators: string[];
  verdict: "clean" | "suspicious" | "malicious";
};

export type UrlAnalysis = {
  target: string;
  verdict: "clean" | "suspicious";
  indicators: string[];
};

export function normalizeScanLimit(value: string | null): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 1 && parsed <= 1024
    ? parsed
    : DEFAULT_MAX_SCAN_MB;
}

async function digest(
  blob: Blob,
  onProgress?: (processedBytes: number, totalBytes: number) => void,
) {
  const [sha256, sha1] = await Promise.all([createSHA256(), createSHA1()]);
  sha256.init();
  sha1.init();

  onProgress?.(0, blob.size);
  for (
    let offset = 0;
    offset < blob.size;
    offset += HASH_CHUNK_SIZE_BYTES
  ) {
    const chunk = new Uint8Array(
      await blob
        .slice(offset, Math.min(offset + HASH_CHUNK_SIZE_BYTES, blob.size))
        .arrayBuffer(),
    );
    sha256.update(chunk);
    sha1.update(chunk);
    onProgress?.(Math.min(blob.size, offset + chunk.byteLength), blob.size);

    // Give the browser a chance to paint progress and handle input between chunks.
    if (offset + chunk.byteLength < blob.size) {
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
    }
  }

  return {
    sha256: sha256.digest("hex"),
    sha1: sha1.digest("hex"),
  };
}

export function detectFileType(bytes: Uint8Array): string {
  const ascii = new TextDecoder().decode(bytes);
  if (bytes[0] === 0x4d && bytes[1] === 0x5a) {
    return "Windows executable header (MZ)";
  }
  if (ascii.startsWith("%PDF-")) return "PDF document";
  if (bytes[0] === 0x89 && ascii.slice(1, 4) === "PNG") return "PNG image";
  if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return "JPEG image";
  }
  if (ascii.startsWith("GIF87a") || ascii.startsWith("GIF89a")) {
    return "GIF image";
  }
  if (
    bytes[0] === 0x50 &&
    bytes[1] === 0x4b &&
    [0x03, 0x05, 0x07].includes(bytes[2])
  ) {
    return "ZIP container";
  }
  if (ascii.startsWith("Rar!\x1a\x07")) return "RAR archive";
  return "Unknown / no recognized signature";
}

export async function inspectFile(
  file: File,
  maxScanMb = DEFAULT_MAX_SCAN_MB,
  onProgress?: (processedBytes: number, totalBytes: number) => void,
): Promise<LocalAnalysis> {
  if (file.size > maxScanMb * 1024 * 1024) {
    const limitLabel =
      maxScanMb >= 1024 ? `${maxScanMb / 1024} GB` : `${maxScanMb} MB`;
    throw new Error(`File exceeds the current ${limitLabel} scan limit.`);
  }

  const { sha256, sha1 } = await digest(file, onProgress);
  const head = new Uint8Array(await file.slice(0, 4096).arrayBuffer());
  const ascii = Array.from(head, (x) =>
    x >= 32 && x <= 126 ? String.fromCharCode(x) : " ",
  ).join("");
  const indicators: string[] = [];
  const lowerName = file.name.toLowerCase();
  const ext = lowerName.split(".").pop() ?? "";
  const fileType = detectFileType(head);
  const expectedExtensions: Record<string, string[]> = {
    "Windows executable header (MZ)": ["exe", "dll", "scr", "cpl"],
    "PDF document": ["pdf"],
    "PNG image": ["png"],
    "JPEG image": ["jpg", "jpeg"],
    "GIF image": ["gif"],
    "ZIP container": ["zip", "docx", "xlsx", "pptx", "odt"],
    "RAR archive": ["rar"],
  };

  if (
    expectedExtensions[fileType] &&
    !expectedExtensions[fileType].includes(ext)
  ) {
    indicators.push(
      `Signature looks like ${fileType}, but the filename extension is .${ext || "(none)"}`,
    );
  }
  if (
    /\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|txt|zip|7z|rar)\.(exe|scr|bat|cmd|com|js|vbs|ps1|msi)$/i.test(
      lowerName,
    )
  ) {
    indicators.push("Double file extension can disguise file type");
  }
  if (/\.(exe|scr|bat|cmd|com|vbs|ps1|msi|hta|js)$/i.test(lowerName)) {
    indicators.push(`Executable or script-like extension (.${ext})`);
  }
  if (file.size === 0) indicators.push("File is empty");
  if (head[0] === 0x4d && head[1] === 0x5a) {
    indicators.push("Windows executable header detected");
  }
  if (ascii.includes("http://") || ascii.includes("https://")) {
    indicators.push("URL text found in the first 4 KB");
  }

  if (["js", "bat", "cmd", "ps1", "vbs", "hta"].includes(ext)) {
    const script = new TextDecoder().decode(head).toLowerCase();
    const checks: Array<[RegExp, string]> = [
      [/\bdownloadstring\s*\(/, "Script contains a download-string pattern"],
      [/\bfrombase64string\s*\(/, "Script contains a Base64-decoding pattern"],
      [/\bwscript\.shell\b/, "Script references the Windows Script Host shell"],
      [/\b(?:invoke-expression|iex)\b/, "Script contains a dynamic-expression pattern"],
      [
        /\b(?:-enc|-encodedcommand)\s+[a-z0-9+/=]{16,}/,
        "Script contains an encoded-command-like pattern",
      ],
    ];
    for (const [pattern, label] of checks) {
      if (pattern.test(script)) indicators.push(label);
    }
  }

  return {
    fileType,
    sha256,
    sha1,
    indicators,
    verdict: indicators.length ? "suspicious" : "clean",
  };
}

export function safeURLAnalysis(input: string): UrlAnalysis {
  const indicators: string[] = [];
  const raw = input.trim();
  let url: URL | null = null;
  const explicitProtocol =
    /^(?:[a-z][a-z\d+.-]*:\/\/|javascript:|data:|file:|mailto:|ftp:)/i.test(
      raw,
    );

  try {
    url = new URL(explicitProtocol ? raw : `https://${raw}`);
  } catch {
    // Local parsing only; this function never makes a network request.
  }

  if (!url) {
    return {
      target: raw.slice(0, 2048),
      verdict: "suspicious",
      indicators: ["Text is not a valid URL; check spelling and formatting"],
    };
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    indicators.push(`Unusual protocol: ${url.protocol}`);
  }
  if (url.protocol !== "https:") indicators.push("Connection is not HTTPS");
  if (url.username || url.password) {
    indicators.push("URL contains embedded login credentials");
  }
  const host = url.hostname.toLowerCase();
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    indicators.push("Uses a raw IP address instead of a domain name");
  }
  if (
    host.startsWith("xn--") ||
    host.split(".").some((part) => part.startsWith("xn--")) ||
    /[^\x00-\x7f]/i.test(host)
  ) {
    indicators.push("Internationalized domain characters may obscure the host");
  }
  if (host.split(".").length > 4) {
    indicators.push("Many subdomains may make the destination harder to recognize");
  }
  if (raw.length > 180) indicators.push("Unusually long URL text");
  if (/%[0-9a-f]{2}/i.test(url.pathname + url.search)) {
    indicators.push("Encoded characters in path or query");
  }

  return {
    target: raw.slice(0, 2048),
    verdict: indicators.length ? "suspicious" : "clean",
    indicators: indicators.length
      ? indicators
      : ["No common local URL warning signs detected"],
  };
}
