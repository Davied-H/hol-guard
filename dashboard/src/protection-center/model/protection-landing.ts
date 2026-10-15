import type { ExtensionCatalogSummary, ExtensionPermission } from "../../extension-controls-api";
import { PROTECTION_CENTER_PERFORMANCE_BUDGETS } from "./protection-performance-budgets";

export type CommandPatternMatch = {
  extension: ExtensionCatalogSummary;
  permission: ExtensionPermission;
  /** Match strength; lower is stronger. 0 names the capability, 2 only mentions it. */
  score: number;
};

export const COMMAND_PATTERN_DISPLAY_LIMIT = 24;

// Ranking bands. A query that appears in the capability's name, label, or
// executable identifies the setting the operator is looking for; a query that
// only appears in prose (for example ".github/workflows" inside a description)
// is an incidental mention and must not outrank the capability it names.
const IDENTITY_MATCH = 0;
const EXAMPLE_MATCH = 1;
const CONTEXT_MATCH = 2;

// Explicit severity order. localeCompare would order the tier names
// alphabetically ("medium" above "critical"), burying the riskiest settings
// at the bottom of the results.
const RISK_TIER_SEVERITY: Record<string, number> = { critical: 3, high: 2, medium: 1, low: 0 };

// Packaged and organization-pushed catalogs speak with the product's voice;
// at equal relevance an extension added locally on this device follows them.
function catalogOriginRank(extension: ExtensionCatalogSummary): number {
  return extension.source === "local-admin" ? 1 : 0;
}

// Bands keep their original case so camelCase humps ("Ocean" in
// "DigitalOcean") still count as word starts.
function patternSearchBands(extension: ExtensionCatalogSummary, permission: ExtensionPermission): [string, string, string] {
  return [
    [permission.label, extension.name, extension.extension_id, ...extension.executables].join(" "),
    [permission.example_command ?? "", permission.permission_id].join(" "),
    [permission.description, permission.family ?? ""].join(" "),
  ];
}

const WORD_CHAR = /[\p{L}\p{N}]/u;
const LOWER = /\p{Ll}/u;
const UPPER = /\p{Lu}/u;

function startsWord(text: string, index: number): boolean {
  if (index === 0) return true;
  const previous = text[index - 1]!;
  return !WORD_CHAR.test(previous) || (LOWER.test(previous) && UPPER.test(text[index]!));
}

// A whole word ends at punctuation or whitespace only: "git" is a prefix of
// "GitHub", not the whole of it.
function endsWord(text: string, end: number): boolean {
  return end >= text.length || !WORD_CHAR.test(text[end]!);
}

/**
 * How `term` (already lowercased) occurs in `text`: "exact" when it is a whole
 * word, "prefix" when it starts a word, null otherwise. A term that only occurs
 * inside a word does not match, so "git" finds Git and GitHub but not
 * DigitalOcean. Terms that start with punctuation ("--force", ".github") match
 * wherever they occur.
 */
export function wordMatch(text: string, term: string): "exact" | "prefix" | null {
  const lower = text.toLowerCase();
  // Case folding that changes length would misalign the case checks below.
  const source = lower.length === text.length ? text : lower;
  const anchored = WORD_CHAR.test(term[0] ?? "");
  const closes = WORD_CHAR.test(term[term.length - 1] ?? "");
  let found: "prefix" | null = null;
  for (let index = lower.indexOf(term); index !== -1; index = lower.indexOf(term, index + 1)) {
    if (anchored && !startsWord(source, index)) continue;
    if (!closes || endsWord(source, index + term.length)) return "exact";
    found = "prefix";
  }
  return found;
}

type TermMatch = { band: number; exact: boolean };

function termMatch(term: string, bands: [string, string, string]): TermMatch | null {
  for (let band = IDENTITY_MATCH; band <= CONTEXT_MATCH; band += 1) {
    const match = wordMatch(bands[band]!, term);
    if (match) return { band, exact: match === "exact" };
  }
  return null;
}

/** The bounded query a pattern search sends: trimmed, lowercased, capped. */
export function commandPatternQuery(rawQuery: string): string {
  const normalized = rawQuery.trim().toLowerCase().slice(0, PROTECTION_CENTER_PERFORMANCE_BUDGETS.humanSearchCharacterCap);
  return normalized.split(/\s+/).filter(Boolean).slice(0, PROTECTION_CENTER_PERFORMANCE_BUDGETS.humanSearchTermCap).join(" ");
}

/**
 * Rank candidate permissions for a query. Candidates come from the catalog's
 * permission search; every query term must still occur in a band.
 */
export function searchCommandPatterns(
  candidates: readonly { extension: ExtensionCatalogSummary; permission: ExtensionPermission }[],
  rawQuery: string,
  limit = COMMAND_PATTERN_DISPLAY_LIMIT,
): CommandPatternMatch[] {
  const query = commandPatternQuery(rawQuery);
  if (!query) return [];
  const terms = query.split(" ");
  const matches: (CommandPatternMatch & { partial: number })[] = [];
  for (const { extension, permission } of candidates) {
    const bands = patternSearchBands(extension, permission);
    const termMatches = terms.map((term) => termMatch(term, bands));
    if (termMatches.some((match) => match === null)) continue;
    const found = termMatches as TermMatch[];
    // The query is as strong as its weakest term: "github export" against a
    // permission whose prose carries "github" and whose example carries
    // "export" scores as a context match.
    const score = Math.max(...found.map((match) => match.band));
    // Within a band, whole-word hits outrank prefixes: "git" lists Git's
    // settings before GitHub's.
    const partial = found.filter((match) => !match.exact).length;
    matches.push({ extension, permission, score, partial });
  }
  return matches
    .sort((left, right) =>
      left.score - right.score ||
      left.partial - right.partial ||
      catalogOriginRank(left.extension) - catalogOriginRank(right.extension) ||
      (RISK_TIER_SEVERITY[right.permission.risk_tier] ?? 0) - (RISK_TIER_SEVERITY[left.permission.risk_tier] ?? 0) ||
      left.permission.label.localeCompare(right.permission.label) ||
      left.extension.name.localeCompare(right.extension.name),
    )
    .slice(0, limit)
    .map(({ partial: _partial, ...match }) => match);
}
