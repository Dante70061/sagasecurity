// Keyword highlighting for raw log lines. Log text is attacker-influenced, so it is only ever rendered
// as React text nodes split around <mark> elements. Never HTML.

import { Fragment, type ReactNode } from "react";

export const HIGHLIGHT_TERMS = [
  "Nmap Scripting Engine",
  "Nmap",
  "WPScan",
  "sqlmap",
  "Nikto",
  "DirBuster",
  "dirb",
  "gobuster",
  "Hydra",
  "wp-login.php",
  "wp-content/uploads",
  "webshell",
  "reverse shell",
  "/bin/sh",
  "/bin/bash",
  "sudo",
  "su ",
  "root",
  "Successful su",
  "Accepted password",
  "Failed password",
  "COMMAND=",
];

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const PATTERN = new RegExp(`(${HIGHLIGHT_TERMS.map(escapeRegExp).join("|")})`, "gi");

/** Split text into plain segments and highlighted segments. Pure, testable without React. */
export function tokenize(text: string): { text: string; hit: boolean }[] {
  const out: { text: string; hit: boolean }[] = [];
  let last = 0;
  for (const m of text.matchAll(PATTERN)) {
    const start = m.index ?? 0;
    if (start > last) out.push({ text: text.slice(last, start), hit: false });
    out.push({ text: m[0], hit: true });
    last = start + m[0].length;
  }
  if (last < text.length) out.push({ text: text.slice(last), hit: false });
  return out;
}

export function Highlight({ text }: { text: string }): ReactNode {
  return (
    <>
      {tokenize(text).map((part, i) =>
        part.hit ? (
          <mark key={i} className="hl">
            {part.text}
          </mark>
        ) : (
          <Fragment key={i}>{part.text}</Fragment>
        ),
      )}
    </>
  );
}
