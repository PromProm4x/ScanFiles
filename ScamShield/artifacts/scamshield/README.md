# ScamShield

ScamShield is a privacy-first file and URL triage app. File checks run in the browser; file contents are not sent to the API. The API stores scan metadata and can optionally look up a SHA-256 hash with VirusTotal.

## What it checks

- SHA-256 and SHA-1 hashes calculated locally in incremental 4 MB chunks
- File signatures and extension mismatches
- Double extensions and selected suspicious script patterns
- URL text for insecure schemes, IP-based hosts, lookalike/punycode hosts, and other visible warning signs
- Optional VirusTotal reputation by hash only

ScamShield does not execute files, open URLs, unpack archives, or upload file contents. URL checks are text analysis only and do not resolve or visit the host. A “clean” result means these limited checks found no known indicator; it is not proof that a file or URL is safe. “Malicious” should be reserved for confirmed external detections.

Browser quarantine stores a separate copy in IndexedDB. It does not move or disable the original file on the computer. The user must explicitly export a quarantined copy to restore it.

## Deployment safety

This initial build does not have sign-in or per-user report isolation. Keep it private; add authentication and account-scoped storage before publishing it for multiple users. The API applies basic in-memory request limits, but it is not a substitute for authentication.

## Development

Requirements: Node.js 20 or newer, pnpm, and a PostgreSQL database.

```sh
pnpm install --frozen-lockfile
pnpm --filter @workspace/db run push
pnpm --filter @workspace/api-server run dev
```

In a second terminal:

```sh
pnpm --filter @workspace/scamshield run dev
```

For the API, set `DATABASE_URL` to the development PostgreSQL connection string. `.env.example` documents the expected variables. To enable hash reputation checks, add `VIRUSTOTAL_API_KEY` as a server-side secret. Never put the key in browser code or a checked-in `.env` file. The app only sends hashes to VirusTotal; it never uploads file contents.

## Windows 10 and 11

Install Node.js and pnpm, set `DATABASE_URL` in the terminal, and run `scripts\windows\start-scamshield.bat` from the project. The script starts the API and web development server in separate command windows. Run the database schema command once before the first launch:

```bat
pnpm --filter @workspace/db run push
```

ScamShield currently runs as a browser app, not as a packaged Windows executable. It uses the API and PostgreSQL service; a standalone desktop installer is not included.

## Stored data and privacy

The API stores report metadata, hashes, and indicators, not file bytes. Saved URL targets have credentials, query strings, and fragments removed. VirusTotal keys are read from the server environment and are never returned by the status endpoint or logged.

## Current limits

File scans support up to 1 GB per file by default. The size limit is configurable in Settings, and file contents remain on the user's device during scanning.

This is a triage aid, not a replacement for endpoint antivirus. It does not include YARA rules, a native Windows quarantine driver, antivirus-engine integration, or a standalone executable. Browser-based quarantine only stores a local copy in that browser profile.
