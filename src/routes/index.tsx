import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import {
  ArrowUpRight,
  ChevronDown,
  Command,
  LayoutDashboard,
  ShieldCheck,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { InvestigationAssistant } from "@/components/security/assistant";
import { SecurityAnalytics, SecurityMetrics } from "@/components/security/analytics";
import { PriorityFindings } from "@/components/security/findings";
import { loadLogSummary } from "@/data/log-summary";
import sagaMark from "@/assets/saga-mark.svg";

export const Route = createFileRoute("/")({
  loader: () => loadLogSummary(),
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
  const summary = Route.useLoaderData();
  const view = summary.ok ? summary.view : null;
  const [active, setActive] = useState("Overview");
  const [shown, setShown] = useState(true);
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
          </div>
          <div className="flex items-center gap-3">
          </div>
        </div>
        {view && shown ? (
          <SecurityMetrics view={view} />
        ) : (
          <div className="panel flex items-center justify-center gap-3 px-5 py-10 text-xs text-muted-foreground">
            <ShieldCheck className="size-5 text-primary" />
            Log counts are hidden. The merged file is unchanged.
          </div>
        )}
        <div className="mb-4 mt-7 flex items-center justify-between">
          <span className="kicker">Investigate & understand</span>
        </div>
        <div className="dashboard-grid">
          <InvestigationAssistant />
          {view && shown ? (
            <SecurityAnalytics view={view} />
          ) : (
            <section className="panel flex min-h-64 flex-col items-center justify-center gap-3 p-8 text-center">
              <ShieldCheck className="size-8 text-muted-foreground" />
              <h2 className="text-sm">Log counts are hidden</h2>
              <p className="text-xs text-muted-foreground">The chart is counted from the merged file when shown.</p>
              <Button variant="outline" size="sm" disabled={!view} onClick={() => setShown(true)}>
                Show log counts
                <ArrowUpRight />
              </Button>
            </section>
          )}
        </div>
        <div className="mb-4 mt-7 flex items-center justify-between">
          <span className="kicker">Focus on what matters</span>
        </div>
        {view && shown ? (
          <PriorityFindings view={view} />
        ) : (
          <section className="panel px-5 py-10 text-center text-xs text-muted-foreground">
            Findings from the merged log are hidden.
          </section>
        )}
      </main>
    </div>
  );
}
