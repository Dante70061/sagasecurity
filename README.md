# Saga Security

Saga Security is a dark-mode cybersecurity investigation dashboard for reviewing merged security telemetry, highlighting suspicious activity, and exploring AI-assisted investigation workflows.

The app is designed as a security operations workspace that surfaces:

- event volume and activity trends
- source and destination IP summaries
- parsed identities from log data
- priority findings grouped by severity
- an investigation assistant for conversational analysis

## Overview

This project loads a sample merged log dataset and transforms it into a security overview that helps analysts answer questions like:

- What are the most active log sources?
- Which events stand out as abnormal?
- Which identities and IPs appear most often?
- What are the highest-priority findings in the dataset?

## Tech stack

- React 19
- TypeScript
- Vite
- TanStack Router
- TanStack Query
- Tailwind CSS
- Recharts
- Vitest
- ESLint + Prettier

## Features

- Security overview dashboard with high-level metrics
- Activity charts showing event volume over time
- Log family distribution visualizations
- Parsed identities and unique IP tracking
- Severity-based findings list
- Browser-persisted investigation conversation history
- AI-style assistant panel for asking investigation questions
- Local UI states for hidden or unavailable log data

## Project structure

```text
.
├── dataset/
│   └── russellmitchell_merged.jsonl   # merged telemetry dataset
├── public/
│   └── saga-mark.svg                  # app branding asset
├── src/
│   ├── assets/
│   ├── components/
│   │   ├── ai-elements/
│   │   ├── security/
│   │   └── ui/
│   ├── data/
│   │   ├── ask-saga.ts
│   │   ├── log-summary.server.ts
│   │   └── log-summary.ts
│   ├── lib/
│   ├── routes/
│   │   ├── __root.tsx
│   │   └── index.tsx
│   ├── styles.css
│   ├── main.tsx
│   └── app.tsx
├── .gitignore
├── .prettierrc
├── bun.lock
├── components.json
├── eslint.config.js
├── package.json
├── requirements.txt
├── roadmap.md
├── tsconfig.json
├── vite.config.ts
├── vitest.config.ts
├── README.md
└── package-lock.json
```

## Data model and analytics

The dashboard reads from `dataset/russellmitchell_merged.jsonl` and computes summary metrics such as:

- total event counts
- log file counts and collector sources
- unique IP addresses
- identities parsed from raw lines
- 24-hour activity comparisons
- Wazuh-style rule-level grouping and severity classification

The log analysis logic is implemented in `src/data/log-summary.server.ts` and is used by the UI to populate the overview, charts, and findings panels.

## Getting started

### Requirements

- Node.js 18+
- npm

### Install dependencies

```bash
npm install
```

### Start the development server

```bash
npm run dev
```

Then open the local Vite URL that appears in the terminal.

### Production build

```bash
npm run build
```

### Preview the production build

```bash
npm run preview
```

### Run tests

```bash
npm test
```

## Available scripts

```bash
npm run dev         # start the Vite dev server
npm run build       # create a production build
npm run preview     # preview the built app locally
npm run lint        # run ESLint
npm run format      # format files with Prettier
npm run test        # run Vitest tests
```

## Investigation workflow

The application is structured around a security operations workflow:

1. Load merged telemetry datasets
2. Summarize signal and anomaly indicators
3. Surface top findings by severity
4. Let the user ask investigation questions in context
5. Persist the conversation locally in the browser for continued analysis