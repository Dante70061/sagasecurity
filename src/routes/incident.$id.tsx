import { createFileRoute, Link, notFound } from "@tanstack/react-router";
import { ChevronLeft } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { IncidentBreakdown } from "@/components/security/incident-breakdown";
import { IncidentNav } from "@/components/security/incident-nav";
import { loadIncidentPage, type QueueSelection } from "@/data/incidents";
import { readDecisions, type Decision, type TriageState } from "@/lib/triage-storage";

const NAME = /^[a-z0-9_-]{1,40}$/i;

function pick(value: unknown): string | undefined {
  return typeof value === "string" && NAME.test(value) ? value : undefined;
}

export const Route = createFileRoute("/incident/$id")({
  validateSearch: (search: Record<string, unknown>): QueueSelection => {
    const out: QueueSelection = {};
    const run = pick(search["run"]);
    const scenario = pick(search["scenario"]);
    if (run) out.run = run;
    if (scenario) out.scenario = scenario;
    return out;
  },
  loaderDeps: ({ search }) => search,
  loader: async ({ params, deps }) => {
    const result = await loadIncidentPage({ data: { id: params.id, ...deps } });
    if (!result.ok && result.error.startsWith("No incident")) throw notFound();
    return result;
  },
  head: ({ params }) => ({ meta: [{ title: `Saga Security | ${params.id}` }] }),
  component: IncidentPage,
});

function IncidentPage() {
  const result = Route.useLoaderData();
  const { id } = Route.useParams();
  const [decisions, setDecisions] = useState<Map<string, Decision>>(new Map());
  const ids = useMemo(
    () => (result.ok ? result.view.queue.incidents.map((i) => i.incident_id) : []),
    [result],
  );
  const run = result.ok ? result.view.queue.run : "";
  useEffect(() => {
    setDecisions(readDecisions(run, ids));
  }, [run, ids]);
  const onStateChange = (incidentId: string, state: TriageState) => {
    setDecisions((prev) => {
      const next = new Map(prev);
      if (state.decision) next.set(incidentId, state.decision);
      else next.delete(incidentId);
      return next;
    });
  };

  return (
    <div className="min-h-screen">
      <header className="border-b border-border bg-[#0e1324]">
        <div className="mx-auto flex max-w-[1360px] flex-wrap items-center justify-between gap-3 px-5 py-3.5 md:px-8">
          <div className="flex flex-wrap items-center gap-4">
            <Link
              to="/"
              className="flex min-h-11 items-center gap-1.5 text-sm text-primary no-underline hover:underline"
            >
              <ChevronLeft className="size-4" aria-hidden="true" />
              Overview
            </Link>
            <span className="text-lg font-semibold">Investigate</span>
          </div>
          {result.ok && (
            <span className="num text-xs text-muted-foreground">
              run {result.view.queue.run}
              {result.view.queue.scenario ? ` · scenario ${result.view.queue.scenario}` : ""} ·{" "}
              {decisions.size} of {result.view.queue.counts.incidents} incidents decided
            </span>
          )}
        </div>
      </header>
      <div className="investigate-layout mx-auto max-w-[1360px] px-5 pb-16 pt-6 md:px-8">
        {result.ok ? (
          <>
            <IncidentNav view={result.view.queue} activeId={id} decisions={decisions} />
            <IncidentBreakdown
              key={`${result.view.queue.run}:${id}`}
              view={result.view}
              onStateChange={onStateChange}
            />
          </>
        ) : (
          <section className="card w-full px-6 py-10 text-center text-sm text-muted-foreground">
            {result.error}{" "}
            <Link to="/" className="text-primary">
              Back to the queue
            </Link>
          </section>
        )}
      </div>
    </div>
  );
}
