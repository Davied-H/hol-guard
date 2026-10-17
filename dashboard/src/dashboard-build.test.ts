import {
  DASHBOARD_BUILD_HEADER,
  DASHBOARD_BUILD_META_NAME,
  DASHBOARD_BUILD_RELOAD_STORAGE_KEY,
  claimStaleBuildReload,
  installStaleBuildGuard,
  isDashboardBuildStale,
  loadCurrentDashboardBuild,
  observeDashboardBuild,
  resetObservedDashboardBuild,
  readLoadedDashboardBuild,
  responseDashboardBuild,
} from "./dashboard-build";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function memoryStorage(): Pick<Storage, "getItem" | "setItem"> & { values: Map<string, string> } {
  const values = new Map<string, string>();
  return {
    values,
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => {
      values.set(key, value);
    },
  };
}

function response(url: string, build: string | null): Pick<Response, "headers" | "url"> {
  const headers = new Headers();
  if (build !== null) headers.set(DASHBOARD_BUILD_HEADER, build);
  return { url, headers };
}

const origin = "http://127.0.0.1:5474";

const doc = {
  querySelector: (selector: string) =>
    selector === `meta[name="${DASHBOARD_BUILD_META_NAME}"]` ? { getAttribute: () => " build-old " } : null,
} as unknown as Pick<Document, "querySelector">;
assert(readLoadedDashboardBuild(doc) === "build-old", "the page reads the build the daemon stamped on its shell");
assert(
  readLoadedDashboardBuild({ querySelector: () => null } as unknown as Pick<Document, "querySelector">) === null,
  "a shell without a stamp (dev server) has no loaded build",
);
assert(readLoadedDashboardBuild(undefined) === null, "no document means no loaded build");

assert(responseDashboardBuild(response(`${origin}/v1/runtime`, "build-new"), origin) === "build-new", "same-origin responses report the server build");
assert(
  responseDashboardBuild(response("http://127.0.0.1:6000/v1/runtime", "build-new"), origin) === null,
  "a daemon on another origin cannot serve this page, so it never marks it stale",
);
assert(responseDashboardBuild(response(`${origin}/v1/runtime`, null), origin) === null, "an older daemon without the header reports nothing");
assert(responseDashboardBuild(response("", "build-new"), origin) === null, "responses without a URL are ignored");

assert(!isDashboardBuildStale({ loadedBuild: "a", serverBuild: null }), "no server build seen yet is not stale");
assert(!isDashboardBuildStale({ loadedBuild: null, serverBuild: "b" }), "an unstamped page is never stale");
assert(!isDashboardBuildStale({ loadedBuild: "a", serverBuild: "a" }), "matching builds are current");
assert(isDashboardBuildStale({ loadedBuild: "a", serverBuild: "b" }), "a different server build marks the tab stale");

const storage = memoryStorage();
assert(!claimStaleBuildReload({ loadedBuild: "a", serverBuild: "a" }, storage), "a current tab never reloads");
assert(claimStaleBuildReload({ loadedBuild: "a", serverBuild: "b" }, storage), "a stale tab claims one reload");
assert(storage.values.get(DASHBOARD_BUILD_RELOAD_STORAGE_KEY) === "b", "the claim records the server build it reloaded for");
assert(!claimStaleBuildReload({ loadedBuild: "a", serverBuild: "b" }, storage), "a tab still stale after reloading does not loop");
assert(claimStaleBuildReload({ loadedBuild: "b", serverBuild: "c" }, storage), "a later update gets its own reload");
assert(!claimStaleBuildReload({ loadedBuild: "a", serverBuild: "b" }, undefined), "without session storage the tab never auto-reloads");
const throwingStorage = {
  getItem: () => {
    throw new Error("blocked");
  },
  setItem: () => undefined,
};
assert(!claimStaleBuildReload({ loadedBuild: "a", serverBuild: "b" }, throwingStorage), "blocked storage falls back to normal handling");

// Tab behavior: a stale tab loads the current bundle when its user returns or
// when it is hidden, and never twice for the same server build.
const originalWindow = (globalThis as { window?: unknown }).window;
const originalDocument = (globalThis as { document?: unknown }).document;
const originalSessionStorage = (globalThis as { sessionStorage?: unknown }).sessionStorage;
const tabStorage = memoryStorage();
const documentListeners = new Map<string, Set<() => void>>();
const windowListeners = new Map<string, Set<() => void>>();
let reloads = 0;
const fakeDocument = {
  visibilityState: "visible",
  querySelector: () => ({ getAttribute: () => "build-old" }),
  addEventListener: (type: string, listener: () => void) => {
    documentListeners.set(type, (documentListeners.get(type) ?? new Set()).add(listener));
  },
  removeEventListener: (type: string, listener: () => void) => {
    documentListeners.get(type)?.delete(listener);
  },
};
(globalThis as { document: unknown }).document = fakeDocument;
(globalThis as { sessionStorage: unknown }).sessionStorage = tabStorage;
(globalThis as { window: unknown }).window = {
  location: {
    origin,
    reload: () => {
      reloads += 1;
    },
    assign: () => {
      reloads += 1;
    },
  },
  addEventListener: (type: string, listener: () => void) => {
    windowListeners.set(type, (windowListeners.get(type) ?? new Set()).add(listener));
  },
  removeEventListener: (type: string, listener: () => void) => {
    windowListeners.get(type)?.delete(listener);
  },
};

const loadedBuild: { value: string | null } = { value: null };
fakeDocument.querySelector = () => (loadedBuild.value === null ? (null as never) : ({ getAttribute: () => loadedBuild.value } as never));

// An unstamped page (dev server) never reloads, however many builds the server reports.
resetObservedDashboardBuild();
observeDashboardBuild(response(`${origin}/v1/runtime`, "build-new"));
assert(!loadCurrentDashboardBuild(), "an unstamped page never reloads");
assert(reloads === 0, "no reload was issued for an unstamped page");

// A stamped tab that matches the server stays put.
loadedBuild.value = "build-new";
assert(!loadCurrentDashboardBuild(), "a current tab never reloads");

// A stale tab on screen keeps working until its user acts.
loadedBuild.value = "build-old";
fakeDocument.visibilityState = "visible";
observeDashboardBuild(response(`${origin}/v1/runtime`, "build-new"));
assert(reloads === 0, "a visible stale tab is not reloaded under its user");

// Returning to it loads the current bundle once.
const stop = installStaleBuildGuard();
for (const listener of windowListeners.get("focus") ?? []) listener();
assert(reloads === 1, "focusing a stale tab loads the current bundle");
for (const listener of documentListeners.get("visibilitychange") ?? []) listener();
assert(reloads === 1, "the same server build is never reloaded for twice");
stop();
assert((documentListeners.get("visibilitychange")?.size ?? 0) === 0, "the guard removes its visibility listener");
assert((windowListeners.get("focus")?.size ?? 0) === 0, "the guard removes its focus listener");

// A hidden stale tab swaps its bundle as soon as it learns it is stale.
tabStorage.values.clear();
fakeDocument.visibilityState = "hidden";
observeDashboardBuild(response(`${origin}/v1/runtime`, "build-new"));
assert(reloads === 2, "a hidden stale tab reloads without waiting");

// Navigating away from a stale tab is a full load of the target.
tabStorage.values.clear();
fakeDocument.visibilityState = "visible";
assert(loadCurrentDashboardBuild("/inbox"), "navigation from a stale tab becomes a full load");
assert(reloads === 3, "the full load is issued");

(globalThis as { window?: unknown }).window = originalWindow;
(globalThis as { document?: unknown }).document = originalDocument;
(globalThis as { sessionStorage?: unknown }).sessionStorage = originalSessionStorage;

console.log("dashboard-build tests passed");
