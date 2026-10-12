import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { PathText, displayPath, tokenizePaths } from "@/components/security/path-text";

describe("path rendering", () => {
  it("strips query strings and middle-truncates long paths", () => {
    const full = "/wp-content/uploads/2022/02/zpinqklqgo-1644232829.6164.php?wp_meta=WyJhIl0=";
    expect(displayPath(full)).toBe("/wp-content/uploads/2022/02/zpinqklqgo-1644232829.6164.php");
    const long = `/var/www/${"a".repeat(80)}/x.php`;
    const shown = displayPath(long);
    expect(shown.length).toBeLessThanOrEqual(70);
    expect(shown).toContain("…");
  });

  it("wraps paths in code spans with the full string as a tooltip, without eating sentence punctuation", () => {
    const text =
      "Paths mentioned: /var/www/site/wp-content/uploads/2022/02/shell.php?x=1 and https://example.test/a/b. Done.";
    const parts = tokenizePaths(text);
    expect(parts.filter((p) => p.path).map((p) => p.text)).toEqual([
      "/var/www/site/wp-content/uploads/2022/02/shell.php?x=1",
      "https://example.test/a/b",
    ]);
    const { container } = render(<PathText text={text} />);
    const codes = [...container.querySelectorAll("code.path")];
    expect(codes.map((c) => c.textContent)).toEqual([
      "/var/www/site/wp-content/uploads/2022/02/shell.php",
      "https://example.test/a/b",
    ]);
    expect(codes[0]?.getAttribute("title")).toBe(
      "/var/www/site/wp-content/uploads/2022/02/shell.php?x=1",
    );
    expect(container.textContent?.endsWith(". Done.")).toBe(true);
  });
});
