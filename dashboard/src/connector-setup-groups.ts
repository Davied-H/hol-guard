import { harnessDisplayName, resolveRequestWorkingDirectory } from "./approval-center-utils";
import type { GuardApprovalRequest } from "./guard-types";
import type { LocalCliItem, LocalCliSurface } from "./local-cli-api";
import { localCliHref } from "./local-cli-links";
import { BULK_BLOCKED_CATEGORY_IDS, BULK_HIGH_CATEGORY_IDS, resolveQueueCategory } from "./queue-state";

/**
 * Inbox rows held only because Guard does not recognise a local tool this
 * device was never set up for share a `connector:<identity_hash>:<action>`
 * queue group. The Inbox shows one setup card per connector; every row stays
 * listed inside it as evidence.
 */
export const CONNECTOR_GROUP_PREFIX = "connector:";
const PROTECT_LIST_HREF = "/extensions";
const IDENTITY_HASH_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;

export type ConnectorSetupGroup = {
  /** `connector:<identity_hash>`, shared by every action row of the connector. */
  key: string;
  identityHash: string;
  /** Rows newest first; each one is still a decidable Inbox row. */
  items: GuardApprovalRequest[];
  /** Calls waiting on this connector, counting merged retries of the same action. */
  callCount: number;
  harnesses: string[];
  latest: GuardApprovalRequest;
  workspaceLabel: string | null;
  caution: boolean;
  cautionCount: number;
  /** Protect entry for this connector, when the local tool list resolves it. */
  cli: LocalCliItem | null;
  setupHref: string;
  /** Top-level command names from the tool's own catalog; never operands. */
  triedCommands: string[];
};

/** The `connector:<identity_hash>` key of a row, or `null` for an ordinary review. */
export function connectorGroupKey(queueGroupId: string | null | undefined): string | null {
  if (typeof queueGroupId !== "string" || !queueGroupId.startsWith(CONNECTOR_GROUP_PREFIX)) return null;
  const identityHash = queueGroupId.slice(CONNECTOR_GROUP_PREFIX.length).split(":")[0] ?? "";
  return IDENTITY_HASH_PATTERN.test(identityHash) ? `${CONNECTOR_GROUP_PREFIX}${identityHash}` : null;
}

export function isConnectorSetupItem(item: GuardApprovalRequest): boolean {
  return item.status === "pending" && connectorGroupKey(item.queue_group_id) !== null;
}

/** Same caution rule as bulk approval and the built-in extension card. */
export function connectorItemNeedsCaution(item: GuardApprovalRequest): boolean {
  if (item.extension_recommendation?.caution === true) return true;
  const categoryId = resolveQueueCategory(item).id;
  return BULK_HIGH_CATEGORY_IDS.has(categoryId) || BULK_BLOCKED_CATEGORY_IDS.has(categoryId);
}

export function connectorSurfaceLabel(surface: LocalCliSurface | null): string {
  if (surface === "mcp") return "MCP server";
  if (surface === "package-scripts") return "Package scripts";
  return "Local CLI";
}

function itemTimestamp(item: GuardApprovalRequest): number {
  const value = new Date(item.last_seen_at ?? item.created_at).getTime();
  return Number.isFinite(value) ? value : 0;
}

function itemCommand(item: GuardApprovalRequest): string | null {
  return item.action_envelope_json?.command ?? item.raw_command_text ?? null;
}

function workspaceLabel(item: GuardApprovalRequest): string | null {
  const directory = resolveRequestWorkingDirectory(item);
  if (directory === null) return null;
  const segments = directory.split(/[\\/]/).filter(Boolean);
  return segments[segments.length - 1] ?? null;
}

/** Catalog command names the rows invoked. Arguments are matched, never shown. */
export function triedCatalogCommands(items: GuardApprovalRequest[], cli: LocalCliItem | null): string[] {
  if (cli === null) return [];
  const topLevel = new Set(cli.commands.filter((command) => command.parent_id === null).map((command) => command.name));
  const tried = new Set<string>();
  for (const item of items) {
    const command = itemCommand(item);
    if (command === null) continue;
    const subcommand = command.trim().split(/\s+/).slice(1).find((token) => !token.startsWith("-"));
    if (subcommand !== undefined && topLevel.has(subcommand)) tried.add(subcommand);
  }
  return [...tried].sort();
}

export function connectorSetupHref(cli: LocalCliItem | null): string {
  return cli === null ? PROTECT_LIST_HREF : localCliHref(cli.cli_id);
}

export function buildConnectorSetupGroups(
  items: GuardApprovalRequest[],
  localClis: readonly LocalCliItem[] = [],
): ConnectorSetupGroup[] {
  const byKey = new Map<string, GuardApprovalRequest[]>();
  for (const item of items) {
    if (!isConnectorSetupItem(item)) continue;
    const key = connectorGroupKey(item.queue_group_id);
    if (key === null) continue;
    const rows = byKey.get(key) ?? [];
    rows.push(item);
    byKey.set(key, rows);
  }
  const groups: ConnectorSetupGroup[] = [];
  for (const [key, rows] of byKey) {
    const sorted = [...rows].sort((a, b) => itemTimestamp(b) - itemTimestamp(a));
    const identityHash = key.slice(CONNECTOR_GROUP_PREFIX.length);
    const cli = localClis.find((entry) => entry.identity_hash === identityHash) ?? null;
    const cautionCount = sorted.filter(connectorItemNeedsCaution).length;
    groups.push({
      key,
      identityHash,
      items: sorted,
      callCount: sorted.reduce((sum, item) => sum + Math.max(1, item.dedupe_count ?? 1), 0),
      harnesses: [...new Set(sorted.map((item) => harnessDisplayName(item.harness)))],
      latest: sorted[0],
      workspaceLabel: workspaceLabel(sorted[0]),
      caution: cautionCount > 0,
      cautionCount,
      cli,
      setupHref: connectorSetupHref(cli),
      triedCommands: triedCatalogCommands(sorted, cli),
    });
  }
  return groups.sort((a, b) => itemTimestamp(b.latest) - itemTimestamp(a.latest));
}

export function countConnectorSetupGroups(items: GuardApprovalRequest[]): number {
  const keys = new Set<string>();
  for (const item of items) {
    if (!isConnectorSetupItem(item)) continue;
    const key = connectorGroupKey(item.queue_group_id);
    if (key !== null) keys.add(key);
  }
  return keys.size;
}
