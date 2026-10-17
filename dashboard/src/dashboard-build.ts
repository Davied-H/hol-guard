// A tab opened before Guard restarted on a new version keeps running the old
// bundle against the new daemon. The old screens then read API shapes they were
// never built for, throw while rendering, and stay broken until a full reload.
// The daemon stamps its bundle fingerprint on the shell (a meta tag) and on
// every response (a header), so the page can tell when it is stale and load
// the matching bundle instead of rendering a broken screen.

export const DASHBOARD_BUILD_HEADER = "X-Guard-Dashboard-Build";
export const DASHBOARD_BUILD_META_NAME = "guard-dashboard-build";
export const DASHBOARD_BUILD_RELOAD_STORAGE_KEY = "hol-guard-dashboard-build-reload";

type BuildStorage = Pick<Storage, "getItem" | "setItem">;

export type DashboardBuildState = {
  loadedBuild: string | null;
  serverBuild: string | null;
};

export function readLoadedDashboardBuild(doc: Pick<Document, "querySelector"> | undefined): string | null {
  const content = doc
    ?.querySelector<HTMLMetaElement>(`meta[name="${DASHBOARD_BUILD_META_NAME}"]`)
    ?.getAttribute("content")
    ?.trim();
  return content ? content : null;
}

export function isDashboardBuildStale(state: DashboardBuildState): boolean {
  return state.loadedBuild !== null && state.serverBuild !== null && state.loadedBuild !== state.serverBuild;
}

/**
 * The server build a response reports, or `null` when the response did not come
 * from the daemon that serves this page. A daemon on another origin (port
 * discovery, update reconnect) cannot serve this document, so it never marks the
 * page stale.
 */
export function responseDashboardBuild(
  response: Pick<Response, "headers" | "url">,
  pageOrigin: string,
): string | null {
  const build = response.headers?.get?.(DASHBOARD_BUILD_HEADER)?.trim();
  if (!build || !response.url) {
    return null;
  }
  try {
    return new URL(response.url).origin === pageOrigin ? build : null;
  } catch {
    return null;
  }
}

/**
 * Whether to leave this document for a fresh load of the matching bundle. Each
 * server build gets one attempt per tab, so a page that still reads stale after
 * reloading falls back to its normal error handling instead of looping.
 */
export function claimStaleBuildReload(state: DashboardBuildState, storage: BuildStorage | undefined): boolean {
  if (!isDashboardBuildStale(state) || !storage || state.serverBuild === null) {
    return false;
  }
  try {
    if (storage.getItem(DASHBOARD_BUILD_RELOAD_STORAGE_KEY) === state.serverBuild) {
      return false;
    }
    storage.setItem(DASHBOARD_BUILD_RELOAD_STORAGE_KEY, state.serverBuild);
    return true;
  } catch {
    return false;
  }
}

let serverBuild: string | null = null;

function currentBuildState(): DashboardBuildState {
  return {
    loadedBuild: typeof document === "undefined" ? null : readLoadedDashboardBuild(document),
    serverBuild,
  };
}

function pageSessionStorage(): BuildStorage | undefined {
  try {
    return typeof sessionStorage === "undefined" ? undefined : sessionStorage;
  } catch {
    return undefined;
  }
}

/** Forget the server build seen so far (tests). */
export function resetObservedDashboardBuild(): void {
  serverBuild = null;
}

export function observeDashboardBuild(response: Pick<Response, "headers" | "url">): void {
  const pageOrigin = typeof window === "undefined" ? undefined : window.location?.origin;
  if (!pageOrigin || !response) {
    return;
  }
  const build = responseDashboardBuild(response, pageOrigin);
  if (build === null) {
    return;
  }
  serverBuild = build;
  // Nobody is looking at a hidden tab, so swap its bundle without interrupting anyone.
  if (typeof document !== "undefined" && document.visibilityState === "hidden") {
    loadCurrentDashboardBuild();
  }
}

/**
 * Reload a stale tab when its user comes back to it. Leaving a screen open
 * across a Guard update is the common way to end up on the old bundle, and
 * returning to it is the one moment a reload costs nothing.
 */
export function installStaleBuildGuard(): () => void {
  if (typeof window === "undefined" || typeof document === "undefined") {
    return () => undefined;
  }
  const check = () => {
    if (document.visibilityState !== "hidden") {
      loadCurrentDashboardBuild();
    }
  };
  document.addEventListener("visibilitychange", check);
  window.addEventListener("focus", check);
  return () => {
    document.removeEventListener("visibilitychange", check);
    window.removeEventListener("focus", check);
  };
}

export function dashboardBuildIsStale(): boolean {
  return isDashboardBuildStale(currentBuildState());
}

/**
 * Load `href` (or reload this page) with the bundle the daemon now serves when
 * this tab runs an older one. Returns `true` when the document is leaving.
 */
export function loadCurrentDashboardBuild(href?: string): boolean {
  if (typeof window === "undefined" || !claimStaleBuildReload(currentBuildState(), pageSessionStorage())) {
    return false;
  }
  if (href) {
    window.location.assign(href);
  } else {
    window.location.reload();
  }
  return true;
}
