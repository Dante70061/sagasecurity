// Renders prose that may contain file paths or URLs. Each one becomes a <code> span that can wrap
// anywhere, shown without its query string and middle-truncated past 70 characters, with the full
// string in a tooltip. React text nodes only; never HTML.

import { Fragment, type ReactNode } from "react";

const PATH_RE = /(https?:\/\/[^\s"'<>]+|\/(?:[\w.-]+\/)+[\w.-]+(?:\?[^\s"'<>]*)?)/g;
const MAX = 70;

export function displayPath(full: string): string {
  const shown = full.split("?")[0] ?? full;
  if (shown.length <= MAX) return shown;
  const keep = Math.floor((MAX - 1) / 2);
  return `${shown.slice(0, keep)}…${shown.slice(-keep)}`;
}

export function tokenizePaths(text: string): { text: string; path: boolean }[] {
  const out: { text: string; path: boolean }[] = [];
  let last = 0;
  for (const m of text.matchAll(PATH_RE)) {
    const start = m.index ?? 0;
    let hit = m[0];
    // a trailing "." or "," belongs to the sentence, not the path
    const trail = /[.,;:]+$/.exec(hit)?.[0] ?? "";
    hit = hit.slice(0, hit.length - trail.length);
    if (start > last) out.push({ text: text.slice(last, start), path: false });
    out.push({ text: hit, path: true });
    last = start + hit.length;
  }
  if (last < text.length) out.push({ text: text.slice(last), path: false });
  return out;
}

export function PathText({ text }: { text: string }): ReactNode {
  return (
    <>
      {tokenizePaths(text).map((part, i) =>
        part.path ? (
          <code key={i} className="path" title={part.text}>
            {displayPath(part.text)}
          </code>
        ) : (
          <Fragment key={i}>{part.text}</Fragment>
        ),
      )}
    </>
  );
}
