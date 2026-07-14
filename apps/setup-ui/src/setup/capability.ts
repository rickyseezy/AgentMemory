const CAPABILITY_PATTERN = /^[A-Za-z0-9_-]{43}$/u;

export function consumeSetupCapability(
  location: Location,
  history: History,
): string | null {
  const fragment = new URLSearchParams(
    location.hash.startsWith("#") ? location.hash.slice(1) : "",
  );
  const entries = [...fragment.entries()];
  history.replaceState(null, "", `${location.pathname}${location.search}`);
  if (entries.length !== 1 || entries[0]?.[0] !== "capability") {
    return null;
  }
  const capability = entries[0][1];
  if (!CAPABILITY_PATTERN.test(capability)) {
    return null;
  }
  return capability;
}
