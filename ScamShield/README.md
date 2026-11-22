# 🛡️ ScamShield

Personal security and scam detection platform for local file inspection, URL analysis, and threat reputation review.

---

## 🚀 Quick Start

### 1-Click Launch (Windows)
Double-click `run.bat` or `start.bat`, or in a terminal run:
```bash
node scripts/src/start-all.mjs
```
or
```bash
pnpm dev
```

The app will start both services:
- **Web Dashboard**: [http://localhost:5173](http://localhost:5173)
- **API Server**: [http://localhost:5000](http://localhost:5000)

---

## 🛠️ Commands

| Command | Description |
|---|---|
| `pnpm dev` | Starts both API server and frontend with live logs |
| `pnpm run build` | Typechecks and builds all packages (`api-server`, `scamshield`, `mockup-sandbox`) |
| `pnpm run typecheck` | Runs TypeScript type checking across the entire monorepo |
| `pnpm test` | Runs the test suite with Vitest |
| `pnpm dev:api` | Runs only the API server (Port 5000) |
| `pnpm dev:web` | Runs only the Vite React frontend (Port 5173) |

---

## 📦 Architecture & Stack

- **Frontend**: React 19, Vite 7, TailwindCSS 4, Radix UI, TanStack Query, Lucide icons, Wouter routing.
- **Backend API**: Node.js, Express 5, Pino logging.
- **Database**: 
  - **Embedded**: High-performance embedded PostgreSQL (`@electric-sql/pglite`) persists to `./data/scamshield-db` out of the box with zero setup required.
  - **External**: Supports external PostgreSQL by setting `DATABASE_URL` in `.env`.
- **Validation & Spec**: Zod, OpenAPI spec (`lib/api-spec`), Orval code-generation.
- **Local Scanner**: Browser-local file hashing (SHA-256, SHA-1 via `hash-wasm`), magic byte signature verification, script heuristics, double extension detection, and URL safety analysis.

