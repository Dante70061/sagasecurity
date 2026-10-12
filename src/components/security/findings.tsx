import { useState } from "react";
import { ArrowDownWideNarrow, ChevronDown, ListFilter, Radar, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { LogView } from "@/data/log-summary";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

export function PriorityFindings({ view }: { view: LogView }) {
  const [severity, setSeverity] = useState("All severities");
  const [sort, setSort] = useState("Priority: high to low");
  const findings = view.findings
    .filter((finding) => severity === "All severities" || finding.severity === severity)
    .sort((a, b) =>
      sort === "Most recent first"
        ? b.lastTs - a.lastTs
        : (b.level ?? -1) - (a.level ?? -1) || b.count - a.count,
    );
  return (
    <section className="panel focus-section" id="findings">
      <div className="panel-heading flex-wrap">
        <div className="flex items-center gap-2.5">
          <ShieldAlert className="size-4 text-primary" />
          <h2>Priority findings</h2>
          <span className="flex h-5 min-w-5 items-center justify-center rounded bg-muted px-1 font-mono text-[10px] text-muted-foreground">
            {findings.length}
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button size="sm" variant="ghost" className="text-muted-foreground">
                <ListFilter className="size-3" />
                {severity}
                <ChevronDown className="size-3" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuRadioGroup value={severity} onValueChange={setSeverity}>
                {["All severities", "Critical", "High", "Medium", "Low"].map((s) => (
                  <DropdownMenuRadioItem key={s} value={s}>
                    {s}
                  </DropdownMenuRadioItem>
                ))}
              </DropdownMenuRadioGroup>
            </DropdownMenuContent>
          </DropdownMenu>
          <span className="hidden h-4 border-l border-border sm:block" />
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button size="sm" variant="ghost" className="text-muted-foreground">
                <ArrowDownWideNarrow className="size-3" />
                {sort}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuRadioGroup value={sort} onValueChange={setSort}>
                {["Priority: high to low", "Most recent first"].map((s) => (
                  <DropdownMenuRadioItem key={s} value={s}>
                    {s}
                  </DropdownMenuRadioItem>
                ))}
              </DropdownMenuRadioGroup>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
      {findings.length ? (
        <div className="max-h-96 overflow-y-auto">
          {findings.map((finding) => (
            <article className="border-b border-border px-5 py-3" key={finding.id}>
              <div className="flex flex-wrap items-start justify-between gap-2">
                <h3 className="text-xs font-medium">{finding.detector}</h3>
                <span className="font-mono text-[10px] text-muted-foreground">
                  {finding.severity ?? "No level"}
                  {finding.level != null ? ` · ${finding.level}` : ""}
                </span>
              </div>
              <p className="mt-1 text-[11px] text-muted-foreground">
                {finding.count.toLocaleString("en-US")} rows · {finding.source} · {finding.host} ·{" "}
                {finding.srcIp ?? "no src ip"} · {finding.location}
              </p>
            </article>
          ))}
        </div>
      ) : (
        <div className="findings-empty">
          <div className="findings-icon">
            <Radar className="size-7" strokeWidth={1.25} />
          </div>
          <div>
            <h3 className="text-sm font-medium">No rows in this severity</h3>
            <p className="max-w-lg text-xs leading-6 text-muted-foreground">
              This file has no Wazuh rule_level in the selected band. AMiner rows have no level and
              stay under All severities.
            </p>
          </div>
        </div>
      )}
      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border px-5 py-3 text-[10px] text-muted-foreground">
        <span className="flex items-center gap-2">
          <span className="size-1.5 rounded-full bg-primary" />
          Grouped from the merged log
        </span>
        <span>Ordered by Wazuh rule_level, then count. No confidence field in the file.</span>
      </div>
    </section>
  );
}
