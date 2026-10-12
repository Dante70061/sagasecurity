import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import {
  ArrowUpRight,
  ChevronDown,
  Command,
  LayoutDashboard,
  LockKeyhole,
  ShieldCheck,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { InvestigationAssistant } from "@/components/security/assistant";
import { SecurityAnalytics, SecurityMetrics } from "@/components/security/analytics";
import { PriorityFindings } from "@/components/security/findings";
import sagaMark from "@/assets/saga-mark.svg";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Saga Security | Security overview" },
      {
        name: "description",
        content:
          "Your AI-assisted security investigation workspace. Explore demo telemetry, ask investigation questions, and review prioritized findings when analysis is ready.",
      },
      { property: "og:title", content: "Saga Security | Security overview" },
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

function Index() {
  const [active, setActive] = useState("Overview");
  const [demo, setDemo] = useState(true);
  return (
    <div className="min-h-screen">
      <header className="border-b border-border bg-card/35">
        <div className="mx-auto flex min-h-20 max-w-[1600px] flex-wrap items-center justify-between gap-4 px-5 md:px-9">
          <a
            href="#overview"
            className="flex items-center gap-3"
            onClick={() => setActive("Overview")}
            aria-label="Saga Security home"
          >
            <img src={sagaMark} alt="" className="h-9 w-8" />
            <div className="flex items-baseline gap-1.5">
              <span className="text-xl font-semibold">saga</span>
              <span className="text-xl font-normal text-muted-foreground">security</span>
              <span className="ml-2 hidden border-l border-border pl-4 text-[10px] text-muted-foreground xl:block">
                Intelligence. Beyond the noise.
              </span>
            </div>
          </a>
          <nav
            className="order-3 flex h-11 w-full items-stretch gap-6 text-xs md:order-none md:h-20 md:w-auto"
            aria-label="Dashboard sections"
          >
            {[
              { name: "Overview", id: "overview", icon: LayoutDashboard },
              { name: "Assistant", id: "assistant", icon: Command },
              { name: "Findings", id: "findings", icon: ShieldCheck },
            ].map(({ name, id, icon: Icon }) => (
              <a
                key={id}
                href={`#${id}`}
                onClick={() => setActive(name)}
                className={`flex items-center gap-2 border-b-2 px-1 transition-colors ${active === name ? "nav-active" : "border-transparent text-muted-foreground hover:text-foreground"}`}
              >
                <Icon className="size-3.5" />
                {name}
              </a>
            ))}
          </nav>
          <div className="flex items-center gap-4">
            <span className="hidden items-center gap-2 text-[10px] text-muted-foreground sm:flex">
              <span className="status-dot" />
              Workspace ready
            </span>
            <span className="hidden h-5 border-l border-border sm:block" />
            <div
              className="flex size-8 items-center justify-center rounded-md border border-border bg-secondary text-[10px] font-medium text-secondary-foreground"
              title="Analyst workspace"
            >
              SA
            </div>
          </div>
        </div>
      </header>
      <main className="workspace focus-section" id="overview">
        <div className="mb-7 flex flex-wrap items-end justify-between gap-4">
          <div>
            <div className="kicker mb-2 flex items-center gap-2">
              <span className="h-px w-4 bg-primary" />
              Security operations workspace
            </div>
            <h1 className="text-[28px] font-medium leading-tight">Security overview</h1>
            <p className="mt-2 text-xs text-muted-foreground">
              A clearer picture of your environment. A smarter place to investigate.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1.5 rounded border border-primary/20 bg-primary/5 px-2.5 py-1.5 text-[10px] text-primary">
              <span className="size-1 rounded-full bg-primary" />
              Demo workspace
            </span>
            <Button variant="outline" size="sm" aria-pressed={demo} onClick={() => setDemo(!demo)}>
              {demo ? "Hide demo data" : "Show demo data"}
            </Button>
          </div>
        </div>
        <div className="mb-6 flex flex-wrap items-center justify-between gap-2 border-l-2 border-primary/70 bg-primary/5 px-4 py-3">
          <p className="flex items-center gap-2 text-[11px] text-secondary-foreground">
            <LockKeyhole className="size-3.5 shrink-0 text-primary" />
            Your workspace is ready. Dataset analysis has not started.
          </p>
          <span className="flex items-center gap-1.5 font-mono text-[9px] text-muted-foreground">
            <span className="size-1.5 rounded-full bg-warning" />
            AWAITING RESULTS
          </span>
        </div>
        {demo ? (
          <SecurityMetrics />
        ) : (
          <div className="panel flex items-center justify-center gap-3 px-5 py-10 text-xs text-muted-foreground">
            <ShieldCheck className="size-5 text-primary" />
            Live security metrics will appear after dataset analysis.
          </div>
        )}
        <div className="mb-4 mt-7 flex items-center justify-between">
          <span className="kicker">Investigate & understand</span>
          <span className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
            <LockKeyhole className="size-3" />
            Analyst workspace
          </span>
        </div>
        <div className="dashboard-grid">
          <InvestigationAssistant />
          {demo ? (
            <SecurityAnalytics />
          ) : (
            <section className="panel flex min-h-64 flex-col items-center justify-center gap-3 p-8 text-center">
              <ShieldCheck className="size-8 text-muted-foreground" />
              <h2 className="text-sm">Analytics awaiting data</h2>
              <p className="text-xs text-muted-foreground">
                No live telemetry or analysis results are available yet.
              </p>
              <Button variant="outline" size="sm" onClick={() => setDemo(true)}>
                View demo analytics
                <ArrowUpRight />
              </Button>
            </section>
          )}
        </div>
        <div className="mb-4 mt-7 flex items-center justify-between">
          <span className="kicker">Focus on what matters</span>
          <span className="text-[10px] text-muted-foreground">Evidence-led. Priority-ordered.</span>
        </div>
        <PriorityFindings />
        <footer className="mt-6 flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4 text-[10px] text-muted-foreground">
          <span className="flex items-center gap-2">
            <img src={sagaMark} alt="" className="h-4 w-3.5" />
            Saga Security<span className="mx-1 text-border">/</span>AI-powered security intelligence
          </span>
          <span className="flex items-center gap-1.5">
            <LockKeyhole className="size-3" />
            Local conversation · Demo analytics · No live analysis
          </span>
        </footer>
      </main>
    </div>
  );
}
