// safeHref is defense-in-depth against a javascript:/data: URL reaching an <a href>. React does NOT sanitize href,
// so a `javascript:…` value there executes on click (rel="noopener" does not stop it). The backend is the
// authoritative guard (KB article URLs are scheme-validated at write time), but any user-authored URL we render as a
// link runs through this too: it returns the URL only when it parses to an http(s) scheme, otherwise "" — the caller
// then renders the value as plain text instead of a clickable link.
export function safeHref(raw: string | undefined | null): string {
  const s = (raw ?? "").trim();
  if (!s) return "";
  try {
    // Resolve against a base so protocol-relative + relative inputs get a concrete scheme to inspect.
    const u = new URL(s, "https://nirvet.invalid/");
    return u.protocol === "http:" || u.protocol === "https:" ? s : "";
  } catch {
    return "";
  }
}
