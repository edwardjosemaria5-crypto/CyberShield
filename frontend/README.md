# CyberShield Frontend

React dashboard for the CyberShield security assessment platform. Talks to the
FastAPI backend in `../backend` (default `http://localhost:8000`, override
with the `VITE_API_BASE_URL` environment variable).

## Pages

| Route | Purpose |
| --- | --- |
| `/` | Home — hero with the scan input, quick focus points |
| `/scan` | Scan workflow — input, progress and completion |
| `/dashboard` | Results — Trust Score gauge, verdict/confidence, module grid, findings, recommendations, threat intel, overall assessment |
| `/history` | Paged list of completed scans with total counts |
| `/report/:scanId` | Full stored report with AI explanation and JSON/CSV/PDF export toolbar |
| `/settings` | Application settings view |

## Stack

- React 19 + React Router 7
- Vite 8 (dev server on `http://localhost:5173`)
- axios (single API client with 120 s timeout and error enrichment)
- Plain CSS modules per feature folder

## Commands

```sh
npm install       # install dependencies
npm run dev       # start the Vite dev server
npm run lint      # ESLint
npm run build     # production build (dist/)
npm run preview   # serve the production build
```

## API Integration

- Base URL: `VITE_API_BASE_URL` (default `http://localhost:8000`).
- The backend's default CORS allowlist already includes `http://localhost:5173`
  and `http://127.0.0.1:5173`, so the dev server works without extra config.
- Scans run via `GET /scan/{target}`; history via `GET /history`; report
  export via `GET /reports/{scan_id}/{json|csv|pdf}`.

## Layout

```
src/
├── pages/          # Home, Scan, Dashboard, History, Report, Settings
├── components/     # dashboard/, scan/, report/, threatintel/, history/,
│                   # layout/, common/
├── context/        # ScanProvider — shared scan state
├── hooks/          # useScan, useHistoryList, useScanReport, usePageTitle…
├── services/       # api.js (axios), scanService.js (endpoint calls)
└── utils/          # assessment narration, formatting, target validation
```