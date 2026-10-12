import { CircleAlert, CircleCheck, TriangleAlert } from "lucide-react";
import { riskLabel, type RiskLevel } from "@/data/triage";

/** Risk is always shown as icon plus text, never color alone. */
export function RiskChip({ level }: { level: RiskLevel }) {
  const Icon = level === "high" ? TriangleAlert : level === "medium" ? CircleAlert : CircleCheck;
  return (
    <span className={`risk-chip risk-${level}`}>
      <Icon className="size-3.5" aria-hidden="true" />
      {riskLabel(level)}
    </span>
  );
}
