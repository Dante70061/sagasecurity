import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { Command, LayoutDashboard, ShieldCheck } from "lucide-react";
import { InvestigationAssistant } from "@/components/security/assistant";
import { IncidentDetail } from "@/components/security/incident-detail";
import { IncidentFunnel, IncidentQueue } from "@/components/security/incident-queue";
import { loadIncidentQueue, type QueueView } from "@/data/incidents";
import sagaMark from "@/assets/saga-mark.svg";

const DEFAULT_RUN = "wilson_test";

export const Route = createFileRoute("/")({
  loader: () => loadIncidentQueue({ data: { run: DEFAULT_RUN } }),
  head: () => ({
    meta: [
      { title: "Saga Security | Security overview" },
      {
        name: "description",
        content:
          "Your AI-assisted security investigation workspace. Review ranked, model-scored incidents and ask the assistant to explain them.",
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
  const initial = Route.useLoaderData();
  const [view, setView] = useState<QueueView | null>(initial.ok ? initial.view : null);
  const [loadError, setLoadError] = useState<string | null>(initial.ok ? null : initial.error);
  const [loading, setLoading] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(
    initial.ok ? (initial.view.incidents[0]?.incident_id ?? null) : null,
  );
  const [active, setActive] = useState("Overview");

  const byId = useMemo(
    () => new Map((view?.incidents ?? []).map((incident) => [incident.incident_id, incident])),
    [view],
  );
  const selected = selectedId ? (byId.get(selectedId) ?? null) : null;

  const reload = async (run: string, scenario?: string) => {
    setLoading(true);
    try {
      const result = await loadIncidentQueue({ data: scenario ? { run, scenario } : { run } });
      if (result.ok) {
        setView(result.view);
        setSelectedId(result.view.incidents[0]?.incident_id ?? null);
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
            <p className="mt-2 text-xs text-muted-foreground">
              {view
                ? `Run ${view.run}${view.scenario ? ` · scenario ${view.scenario}` : ""} · incidents ranked for triage, scored by the window model.`
                : "Incidents are not available."}
            </p>
          </div>
        </div>
        {view ? (
          <IncidentFunnel view={view} />
        ) : (
          <div className="panel flex items-center justify-center gap-3 px-5 py-10 text-xs text-muted-foreground">
            <ShieldCheck className="size-5 text-primary" />
            {loadError ?? "The incident list could not be read."}
          </div>
        )}
        <div className="mb-4 mt-7 flex items-center justify-between">
          <span className="kicker">Investigate & understand</span>
          {loadError && view && <span className="text-[10px] text-warning">{loadError}</span>}
        </div>
        <div className="dashboard-grid">
          <InvestigationAssistant
            run={view?.run ?? DEFAULT_RUN}
            scenario={view?.scenario ?? null}
          />
          <IncidentDetail incident={selected} byId={byId} onSelect={setSelectedId} />
        </div>
        <div className="mb-4 mt-7 flex items-center justify-between">
          <span className="kicker">Focus on what matters</span>
          <span className="text-[10px] text-muted-foreground">
            Confirmed by model first, then below threshold. Within a group, highest peak z first.
          </span>
        </div>
        {view ? (
          <IncidentQueue
            view={view}
            selectedId={selectedId}
            loading={loading}
            onSelect={setSelectedId}
            onRunChange={(run) => void reload(run)}
            onScenarioChange={(scenario) =>
              void reload(view.run, scenario === "all" ? undefined : scenario)
            }
          />
        ) : (
          <section className="panel px-5 py-10 text-center text-xs text-muted-foreground">
            No incident queue to show.
          </section>
        )}
      </main>
    </div>
  );
}
