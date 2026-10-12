import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Command, LayoutDashboard, Search, ShieldCheck } from "lucide-react";
import { InvestigationAssistant } from "@/components/security/assistant";
import {
  AblationPanel,
  AttackTimeline,
  FunnelTiles,
  HostBars,
  OutcomeDonut,
  SensorDonut,
} from "@/components/security/console-charts";
import { IncidentTable } from "@/components/security/incident-table";
import { loadIncidentQueue, type QueueView } from "@/data/incidents";
import sagaMark from "@/assets/saga-mark.svg";

const DEFAULT_RUN = "wilson_test";
const ASK_ID = /^INC-\d{4}$/;

export const Route = createFileRoute("/")({
  validateSearch: (search: Record<string, unknown>): { ask?: string } => {
    const ask = search["ask"];
    return typeof ask === "string" && ASK_ID.test(ask) ? { ask } : {};
  },
  loader: () => loadIncidentQueue({ data: { run: DEFAULT_RUN } }),
  head: () => ({
    meta: [
      { title: "Saga Security · Triage" },
      {
        name: "description",
        content:
          "Your AI-assisted security investigation workspace. Review ranked, model-scored incidents and ask the assistant to explain them.",
      },
      { property: "og:title", content: "Saga Security · Triage" },
      {
        property: "og:description",
        content:
          "An intelligent workspace for cybersecurity investigation, analytics, and prioritized findings.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Index,
});

const sections = [
  { name: "Triage", id: "triage", icon: LayoutDashboard },
  { name: "Findings", id: "findings", icon: ShieldCheck },
  { name: "Assistant", id: "assistant", icon: Command },
];

function scrollToSection(id: string) {
  if (id === "triage") {
    window.scrollTo({ top: 0, behavior: "smooth" });
    return;
  }
  document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
}

function Picker({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: { value: string; label: string }[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="flex items-center gap-2 text-xs text-muted-foreground">
      {label}
      <select
        aria-label={label}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="min-h-10 rounded-lg border border-[#2a3352] bg-[#151b30] px-2.5 py-2 text-[13px] text-foreground focus:outline-none focus:ring-2 focus:ring-primary"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}

const MONTH = { month: "short", timeZone: "UTC" } as const;

/** "wilson · Feb 5–7, 2022 · 10 incidents need review", all from the queue data. */
function statusLine(view: QueueView): string {
  const pool = view.incidents.filter((i) => i.group === "confirmed");
  const span = pool.length ? pool : view.incidents;
  const starts = span.map((i) => Date.parse(i.start));
  const ends = span.map((i) => Date.parse(i.end));
  let range = "";
  if (starts.length) {
    const a = new Date(Math.min(...starts));
    const b = new Date(Math.max(...ends));
    const ma = a.toLocaleDateString("en-US", MONTH);
    const mb = b.toLocaleDateString("en-US", MONTH);
    const da = a.getUTCDate();
    const db = b.getUTCDate();
    range =
      ma === mb && da === db
        ? `${ma} ${da}, ${b.getUTCFullYear()}`
        : ma === mb
          ? `${ma} ${da}–${db}, ${b.getUTCFullYear()}`
          : `${ma} ${da} – ${mb} ${db}, ${b.getUTCFullYear()}`;
  }
  const where = view.scenario ?? view.run;
  const need = view.counts.confirmed;
  return [
    where,
    range,
    `${need} incident${need === 1 ? "" : "s"} need${need === 1 ? "s" : ""} review`,
  ]
    .filter(Boolean)
    .join(" · ");
}

function runLabel(run: string): string {
  return run === "wilson_test"
    ? "wilson_test · held out"
    : run === "dev"
      ? "dev · 7 scenarios"
      : run;
}

function Index() {
  const initial = Route.useLoaderData();
  const { ask } = Route.useSearch();
  const [view, setView] = useState<QueueView | null>(initial.ok ? initial.view : null);
  const [loadError, setLoadError] = useState<string | null>(initial.ok ? null : initial.error);
  const [loading, setLoading] = useState(false);
  const [active, setActive] = useState("Triage");
  const [compact, setCompact] = useState(false);

  const reload = async (run: string, scenario?: string) => {
    setLoading(true);
    try {
      const result = await loadIncidentQueue({ data: scenario ? { run, scenario } : { run } });
      if (result.ok) {
        setView(result.view);
        setLoadError(null);
      } else {
        setLoadError(result.error);
      }
    } catch {
      setLoadError("The incident list could not be read.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const markers = sections.filter((section) => section.id !== "triage");
    let frame = 0;
    let lastY = window.scrollY;
    let travel = 0;
    let compactNow = false;
    let holdUntil = 0;
    const update = () => {
      frame = 0;
      const maxScroll = document.documentElement.scrollHeight - window.innerHeight;
      let name = "Triage";
      for (const section of markers) {
        const el = document.getElementById(section.id);
        if (!el) continue;
        const top = el.getBoundingClientRect().top;
        const topAtEnd = top + window.scrollY - maxScroll;
        const line = Math.max(180, topAtEnd + 48);
        if (top <= line) name = section.name;
      }
      setActive((current) => (current === name ? current : name));
    };
    const onScroll = () => {
      const y = window.scrollY;
      const delta = y - lastY;
      lastY = y;
      if (performance.now() < holdUntil) {
        lastY = y;
        travel = 0;
      } else if (y <= 40) {
        travel = 0;
        if (compactNow) {
          compactNow = false;
          holdUntil = performance.now() + 360;
          setCompact(false);
        }
      } else if (delta !== 0) {
        if ((delta > 0 && travel < 0) || (delta < 0 && travel > 0)) travel = 0;
        travel += delta;
        if (travel > 24 && !compactNow) {
          compactNow = true;
          holdUntil = performance.now() + 360;
          setCompact(true);
        } else if (travel < -24 && compactNow) {
          compactNow = false;
          holdUntil = performance.now() + 360;
          setCompact(false);
        }
      }
      if (!frame) frame = requestAnimationFrame(update);
    };
    update();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => {
      window.removeEventListener("scroll", onScroll);
      if (frame) cancelAnimationFrame(frame);
    };
  }, []);

  const top = view?.incidents[0];

  return (
    <div className="min-h-screen">
      <header
        data-compact={compact ? "true" : "false"}
        className="topbar sticky top-0 z-30 border-b border-border bg-card/95 backdrop-blur-md"
      >
        <div className="topbar-row mx-auto flex max-w-[1360px] flex-wrap items-center justify-between gap-4 px-5 md:px-8">
          <a
            href="#triage"
            className="flex items-center gap-3"
            onClick={(event) => {
              event.preventDefault();
              setActive("Triage");
              scrollToSection("triage");
            }}
            aria-label="Saga Security home"
          >
            <img src={sagaMark} alt="" className="topbar-mark" />
            <div className="flex items-baseline gap-1.5">
              <span className="topbar-word font-semibold">saga</span>
              <span className="topbar-word font-normal text-muted-foreground">security</span>
            </div>
          </a>
          <nav
            className="topbar-nav order-3 flex w-full items-stretch gap-6 text-xs md:order-none md:w-auto"
            aria-label="Dashboard sections"
          >
            {sections.map(({ name, id, icon: Icon }) => (
              <a
                key={id}
                href={`#${id}`}
                aria-current={active === name ? "true" : undefined}
                onClick={(event) => {
                  event.preventDefault();
                  setActive(name);
                  scrollToSection(id);
                }}
                className={`flex items-center gap-2 border-b-2 px-1 transition-colors ${active === name ? "nav-active" : "border-transparent text-muted-foreground hover:text-foreground"}`}
              >
                <Icon className="size-3.5" />
                {name}
              </a>
            ))}
            {view && top && (
              <Link
                to="/incident/$id"
                params={{ id: top.incident_id }}
                search={{ run: view.run }}
                className="flex items-center gap-2 border-b-2 border-transparent px-1 text-muted-foreground no-underline transition-colors hover:text-foreground"
              >
                <Search className="size-3.5" />
                Investigate
              </Link>
            )}
          </nav>
          {view && (
            <div className="flex flex-wrap gap-2.5">
              <Picker
                label="Run"
                value={view.run}
                options={view.runs.map((r) => ({ value: r, label: runLabel(r) }))}
                onChange={(run) => void reload(run)}
              />
              {view.scenarios.length > 1 && (
                <Picker
                  label="Scenario"
                  value={view.scenario ?? "all"}
                  options={[
                    { value: "all", label: "all" },
                    ...view.scenarios.map((s) => ({ value: s, label: s })),
                  ]}
                  onChange={(scenario) =>
                    void reload(view.run, scenario === "all" ? undefined : scenario)
                  }
                />
              )}
            </div>
          )}
        </div>
      </header>

      <main
        id="triage"
        className="mx-auto flex max-w-[1360px] flex-col gap-7 px-5 pb-16 pt-8 md:px-8"
        aria-busy={loading}
      >
        <section className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-1">
          <h1 className="m-0 text-lg font-semibold">Triage</h1>
          {view && <p className="m-0 text-xs text-muted-foreground">{statusLine(view)}</p>}
        </section>

        {view ? (
          <>
            <FunnelTiles view={view} />
            <AttackTimeline view={view} />
            <section aria-labelledby="charts-title" className="flex flex-col gap-3">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <h2 id="charts-title" className="section-title">
                  What the data shows
                </h2>
              </div>
              <div className="console-grid">
                <SensorDonut view={view} />
                <OutcomeDonut view={view} />
                <HostBars view={view} />
                <AblationPanel />
              </div>
            </section>
            <section id="findings" className="focus-section">
              <IncidentTable view={view} />
            </section>
          </>
        ) : (
          <div className="card px-5 py-10 text-center text-xs text-muted-foreground">
            {loadError ?? "The incident list could not be read."}
          </div>
        )}
        {loadError && view && <p className="text-xs text-warning">{loadError}</p>}

        <section id="assistant" className="focus-section">
          <InvestigationAssistant
            run={view?.run ?? DEFAULT_RUN}
            scenario={view?.scenario ?? null}
            prefill={
              ask
                ? `Explain ${ask}: what happened, why it was flagged, and what I should check next.`
                : null
            }
          />
        </section>

        <footer className="flex flex-wrap gap-x-6 gap-y-2 border-t border-[#1e2640] pt-4 text-xs text-muted-foreground">
          <span>Not visible in IDS alerts: offline password cracking · DNS exfiltration</span>
          <span>
            Pipeline: per-host robust z-scores → logistic regression (p_attack) → LLM summary
          </span>
        </footer>
      </main>
    </div>
  );
}
