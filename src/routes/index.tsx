import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Command, LayoutDashboard, ShieldCheck } from "lucide-react";
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

const sections = [
  { name: "Overview", id: "overview", icon: LayoutDashboard },
  { name: "Assistant", id: "assistant", icon: Command },
  { name: "Findings", id: "findings", icon: ShieldCheck },
];

function scrollToSection(id: string) {
  if (id === "overview") {
    window.scrollTo({ top: 0, behavior: "smooth" });
    return;
  }
  document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
}

function Index() {
  const summary = Route.useLoaderData();
  const view = summary.ok ? summary.view : null;
  const [active, setActive] = useState("Overview");
  const [compact, setCompact] = useState(false);
  useEffect(() => {
    const markers = sections.filter((section) => section.id !== "overview");
    let frame = 0;
    let lastY = window.scrollY;
    let travel = 0;
    let compactNow = false;
    let holdUntil = 0;
    const update = () => {
      frame = 0;
      let name = "Overview";
      for (const section of markers) {
        const el = document.getElementById(section.id);
        if (el && el.getBoundingClientRect().top <= 180) name = section.name;
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
  return (
    <div className="min-h-screen">
      <header
        data-compact={compact ? "true" : "false"}
        className="topbar sticky top-0 z-30 border-b border-border bg-card/95 backdrop-blur-md"
      >
        <div className="topbar-row mx-auto flex max-w-[1600px] flex-wrap items-center justify-between gap-4 px-5 md:px-9">
          <a
            href="#overview"
            className="flex items-center gap-3"
            onClick={(event) => {
              event.preventDefault();
              setActive("Overview");
              scrollToSection("overview");
            }}
            aria-label="Saga Security home"
          >
            <img src={sagaMark} alt="" className="topbar-mark" />
            <div className="flex items-baseline gap-1.5">
              <span className="topbar-word font-semibold">saga</span>
              <span className="topbar-word font-normal text-muted-foreground">security</span>
            </div>
          </a>
          <nav className="topbar-nav order-3 flex w-full items-stretch gap-6 text-xs md:order-none md:w-auto" aria-label="Dashboard sections">
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
          </nav>
        </div>
      </header>
      <main className="workspace focus-section" id="overview">
        <h1 className="zone-title mb-7">Overview</h1>
        {view ? (
          <>
            <SecurityMetrics view={view} />
            <SecurityAnalytics view={view} />
          </>
        ) : (
          <div className="panel flex items-center justify-center gap-3 px-5 py-10 text-xs text-muted-foreground">
            <ShieldCheck className="size-5 text-primary" />
            Log counts are hidden. The merged file is unchanged.
          </div>
        )}
        <section id="assistant" className="focus-section mt-7">
          <h2 className="zone-title mb-4">Assistant</h2>
          <InvestigationAssistant />
        </section>
        <section id="findings" className="focus-section mt-[22px]">
          <h2 className="zone-title mb-4">Findings</h2>
          {view ? (
            <PriorityFindings view={view} />
          ) : (
            <section className="panel px-5 py-10 text-center text-xs text-muted-foreground">
              Findings from the merged log are hidden.
            </section>
          )}
        </section>
      </main>
    </div>
  );
}
