import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Highlight, tokenize } from "@/components/security/highlight";

describe("sample alert highlighting", () => {
  it("splits known tool names into mark elements", () => {
    const parts = tokenize(
      '"GET /HNAP1 HTTP/1.1" 404 "Mozilla/5.0 (compatible; Nmap Scripting Engine)"',
    );
    expect(parts.filter((p) => p.hit).map((p) => p.text)).toEqual(["Nmap Scripting Engine"]);
    expect(parts.map((p) => p.text).join("")).toBe(
      '"GET /HNAP1 HTTP/1.1" 404 "Mozilla/5.0 (compatible; Nmap Scripting Engine)"',
    );
  });

  it("renders attacker-controlled markup as plain text, never as HTML", () => {
    const raw = "<script>alert(1)</script><img src=x onerror=alert(2)> GET /wp-login.php by Nmap";
    const { container } = render(<Highlight text={raw} />);
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toBe(raw);
    const marks = [...container.querySelectorAll("mark")].map((m) => m.textContent);
    expect(marks).toEqual(["wp-login.php", "Nmap"]);
  });
});
