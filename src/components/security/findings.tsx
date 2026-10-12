import { useState } from "react";
import { ArrowDownWideNarrow, ChevronDown, ListFilter, Radar, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

export function PriorityFindings() {
  const [severity, setSeverity] = useState("All severities");
  const [sort, setSort] = useState("Priority: high to low");
  return (
    <section className="panel focus-section" id="findings">
      <div className="panel-heading flex-wrap">
        <div className="flex items-center gap-2.5">
          <ShieldAlert className="size-4 text-primary" />
          <h2>Priority findings</h2>
          <span className="flex size-5 items-center justify-center rounded bg-muted font-mono text-[10px] text-muted-foreground">
            —
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
      <div className="findings-empty">
        <div className="findings-icon">
          <Radar className="size-7" strokeWidth={1.25} />
        </div>
        <div>
          <div className="mb-2 flex items-center gap-2 max-sm:justify-center">
            <h3 className="text-sm font-medium">Awaiting analysis results</h3>
            <span className="demo-badge">PENDING</span>
          </div>
          <p className="max-w-lg text-xs leading-6 text-muted-foreground">
            Findings will appear here once your dataset has been processed.
            <br className="hidden sm:block" />
            No security assessment has been completed yet.
          </p>
        </div>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border px-5 py-3 text-[10px] text-muted-foreground">
        <span className="flex items-center gap-2">
          <span className="size-1.5 rounded-full bg-warning" />
          Analysis pending
        </span>
        <span>Prioritized by severity, confidence, and potential impact</span>
      </div>
    </section>
  );
}
