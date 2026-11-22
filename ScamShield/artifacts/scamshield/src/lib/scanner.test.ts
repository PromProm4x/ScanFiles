import { File } from "node:buffer";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  detectFileType,
  HASH_CHUNK_SIZE_BYTES,
  inspectFile,
  normalizeScanLimit,
  safeURLAnalysis,
} from "./scanner";

describe("file inspection", () => {
  it("calculates SHA-256 and SHA-1 locally", async () => {
    const report = await inspectFile(new File(["hello"], "note.txt"));
    expect(report.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(report.sha1).toMatch(/^[a-f0-9]{40}$/);
    expect(report.verdict).toBe("clean");
  });

  it("hashes files across multiple chunks without changing the digest", async () => {
    const bytes = new Uint8Array(HASH_CHUNK_SIZE_BYTES + 37);
    for (let i = 0; i < bytes.length; i += 1) bytes[i] = i % 251;
    const file = new File([bytes], "large-sample.bin");
    const report = await inspectFile(file);

    expect(report.sha256).toBe(createHash("sha256").update(bytes).digest("hex"));
    expect(report.sha1).toBe(createHash("sha1").update(bytes).digest("hex"));
  });

  it("recognizes common signatures independently of filenames", () => {
    expect(detectFileType(new TextEncoder().encode("%PDF-1.7"))).toBe(
      "PDF document",
    );
    expect(detectFileType(new Uint8Array([0x89, 0x50, 0x4e, 0x47]))).toBe(
      "PNG image",
    );
  });

  it("flags a file whose PDF signature conflicts with its extension", async () => {
    const report = await inspectFile(new File(["%PDF-1.7"], "invoice.png"));
    expect(report.fileType).toBe("PDF document");
    expect(report.verdict).toBe("suspicious");
    expect(report.indicators.join(" ")).toContain("filename extension");
  });

  it("flags double extensions and suspicious script indicators", async () => {
    const disguised = await inspectFile(
      new File(["plain text"], "invoice.pdf.exe"),
    );
    expect(disguised.indicators).toContain(
      "Double file extension can disguise file type",
    );

    const script = await inspectFile(
      new File(["WScript.Shell"], "sample.vbs"),
    );
    expect(script.indicators).toContain(
      "Script references the Windows Script Host shell",
    );
  });

  it("rejects files over the configured limit before reading them", async () => {
    const file = new File(["123456"], "sample.txt");
    await expect(inspectFile(file, 1 / 1024 / 1024)).rejects.toThrow(
      "scan limit",
    );
  });

  it("uses a bounded default when a saved size preference is invalid", () => {
    expect(normalizeScanLimit(null)).toBe(1024);
    expect(normalizeScanLimit("2048")).toBe(1024);
    expect(normalizeScanLimit("500")).toBe(500);
    expect(normalizeScanLimit("50")).toBe(50);
  });
});

describe("URL text analysis", () => {
  it("flags plain HTTP and raw IP destinations without visiting them", () => {
    const result = safeURLAnalysis("http://192.0.2.1/sign-in");
    expect(result.verdict).toBe("suspicious");
    expect(result.indicators).toContain("Connection is not HTTPS");
    expect(result.indicators).toContain(
      "Uses a raw IP address instead of a domain name",
    );
  });

  it("flags non-web protocols rather than treating them as web links", () => {
    const result = safeURLAnalysis("javascript:alert(1)");
    expect(result.verdict).toBe("suspicious");
    expect(result.indicators.some((item) => item.includes("Unusual protocol"))).toBe(
      true,
    );
  });

  it("flags internationalized host encodings", () => {
    const result = safeURLAnalysis("https://xn--example-9d0b.example");
    expect(result.verdict).toBe("suspicious");
    expect(result.indicators.some((item) => item.includes("Internationalized"))).toBe(
      true,
    );
  });
});
