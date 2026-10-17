import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent } from "react";
import {
  HiMiniArrowDown,
  HiMiniArrowUp,
  HiMiniFunnel,
  HiMiniMagnifyingGlass,
  HiMiniXMark,
} from "react-icons/hi2";
import { ActionButton, IconActionButton } from "./approval-center-primitives";
import { GuardModalLayer } from "./guard-modal-layer";
import { Select } from "./select";
import type {
  PackageWorkbenchFilters,
  PackageWorkbenchSortKey,
} from "./guard-types";

type FilterModalView = "filters" | "sort";

type FilterModalContentProps = {
  filters: PackageWorkbenchFilters;
  ecosystems: string[];
  onEcosystemChange: (ecosystem: string) => void;
  onDecisionChange: (decision: PackageWorkbenchFilters["decision"]) => void;
  onSeverityChange: (severity: PackageWorkbenchFilters["severity"]) => void;
};

function FilterModalContent({
  filters,
  ecosystems,
  onEcosystemChange,
  onDecisionChange,
  onSeverityChange,
}: FilterModalContentProps) {
  const options = useMemo(() => {
    return {
      ecosystems: ["all", ...ecosystems],
      decisions: ["all", "block", "ask", "warn", "monitor", "allow"] as PackageWorkbenchFilters["decision"][],
      severities: ["all", "critical", "high", "medium", "low", "unknown"] as PackageWorkbenchFilters["severity"][],
    };
  }, [ecosystems]);

  const handleEcosystemChange = useCallback(
    (value: string) => onEcosystemChange(value),
    [onEcosystemChange],
  );
  const handleDecisionChange = useCallback(
    (value: string) => onDecisionChange(value as PackageWorkbenchFilters["decision"]),
    [onDecisionChange],
  );
  const handleSeverityChange = useCallback(
    (value: string) => onSeverityChange(value as PackageWorkbenchFilters["severity"]),
    [onSeverityChange],
  );

  return (
    <div className="space-y-4">
      <label className="block">
        <span className="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-400">Ecosystem</span>
        <Select
          value={filters.ecosystem}
          onValueChange={handleEcosystemChange}
          className="mt-1.5 w-full"
          options={options.ecosystems.map((value) => ({
            value,
            label: value === "all" ? "All ecosystems" : value,
          }))}
        />
      </label>
      <label className="block">
        <span className="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-400">Decision</span>
        <Select
          value={filters.decision}
          onValueChange={handleDecisionChange}
          className="mt-1.5 w-full"
          options={options.decisions.map((value) => ({
            value,
            label: value === "all" ? "All decisions" : value,
          }))}
        />
      </label>
      <label className="block">
        <span className="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-400">Severity</span>
        <Select
          value={filters.severity}
          onValueChange={handleSeverityChange}
          className="mt-1.5 w-full"
          options={options.severities.map((value) => ({
            value,
            label: value === "all" ? "All severities" : value,
          }))}
        />
      </label>
    </div>
  );
}

function SortModalContent({
  sortKey,
  sortDirection,
  onSortChange,
}: {
  sortKey: PackageWorkbenchSortKey;
  sortDirection: "asc" | "desc";
  onSortChange: (sortKey: PackageWorkbenchSortKey) => void;
}) {
  const handleSortChange = useCallback(
    (value: string) => onSortChange(value as PackageWorkbenchSortKey),
    [onSortChange],
  );
  const toggleDirection = useCallback(() => {
    onSortChange(sortKey);
  }, [onSortChange, sortKey]);

  return (
    <div className="space-y-4">
      <label className="block">
        <span className="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-400">Sort by</span>
        <Select
          value={sortKey}
          onValueChange={handleSortChange}
          className="mt-1.5 w-full"
          options={[
            { value: "severity", label: "Severity" },
            { value: "package", label: "Package" },
            { value: "ecosystem", label: "Ecosystem" },
            { value: "decision", label: "Decision" },
          ]}
        />
      </label>
      <button
        type="button"
        onClick={toggleDirection}
        className="flex w-full items-center justify-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50 focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
      >
        {sortDirection === "desc" ? (
          <>
            <HiMiniArrowDown className="h-4 w-4" aria-hidden="true" /> Descending
          </>
        ) : (
          <>
            <HiMiniArrowUp className="h-4 w-4" aria-hidden="true" /> Ascending
          </>
        )}
      </button>
    </div>
  );
}

export type FilterModalProps = {
  filters: PackageWorkbenchFilters;
  activeFilterCount: number;
  ecosystems: string[];
  sortKey: PackageWorkbenchSortKey;
  sortDirection: "asc" | "desc";
  onClose: () => void;
  onSearchChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onEcosystemChange: (ecosystem: string) => void;
  onDecisionChange: (decision: PackageWorkbenchFilters["decision"]) => void;
  onSeverityChange: (severity: PackageWorkbenchFilters["severity"]) => void;
  onSortChange: (sortKey: PackageWorkbenchSortKey) => void;
  onClearFilters: () => void;
};

export function FilterModal({
  filters,
  activeFilterCount,
  ecosystems,
  sortKey,
  sortDirection,
  onClose,
  onSearchChange,
  onEcosystemChange,
  onDecisionChange,
  onSeverityChange,
  onSortChange,
  onClearFilters,
}: FilterModalProps) {
  const [activeView, setActiveView] = useState<FilterModalView>("filters");
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (searchRef.current) {
      searchRef.current.focus();
    }
  }, [activeView]);

  const handleClearSearch = useCallback(() => {
    onSearchChange({ target: { value: "" } } as ChangeEvent<HTMLInputElement>);
  }, [onSearchChange]);

  return (
    <GuardModalLayer ariaLabel="Filter and sort package findings" onClose={onClose} panelClassName="w-full max-w-md">
      <div className="max-h-[min(85vh,44rem)] overflow-y-auto rounded-2xl border border-slate-100 bg-white shadow-xl">
        <div className="sticky top-0 z-10 flex items-center justify-between border-b border-slate-100 bg-white/95 px-4 py-3 backdrop-blur-sm">
          <div className="flex items-center gap-2">
            <HiMiniFunnel className="h-4 w-4 text-slate-500" aria-hidden="true" />
            <p className="text-sm font-semibold text-brand-dark">Filters</p>
            {activeFilterCount > 0 ? (
              <span className="rounded-full bg-brand-blue px-2 py-0.5 text-[10px] font-semibold text-white">
                {activeFilterCount}
              </span>
            ) : null}
          </div>
          <IconActionButton
            variant="ghost"
            label="Close filters"
            icon={<HiMiniXMark className="h-4 w-4" />}
            onClick={onClose}
          />
        </div>
        <div className="px-4 py-4">
          <div className="flex gap-2 border-b border-slate-100 pb-4">
            <button
              type="button"
              onClick={() => setActiveView("filters")}
              aria-pressed={activeView === "filters"}
              className={`flex-1 rounded-lg px-3 py-2 text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${
                activeView === "filters" ? "bg-brand-blue/10 text-brand-blue" : "text-slate-600 hover:bg-slate-50"
              }`}
            >
              Filters
            </button>
            <button
              type="button"
              onClick={() => setActiveView("sort")}
              aria-pressed={activeView === "sort"}
              className={`flex-1 rounded-lg px-3 py-2 text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${
                activeView === "sort" ? "bg-brand-blue/10 text-brand-blue" : "text-slate-600 hover:bg-slate-50"
              }`}
            >
              Sort
            </button>
          </div>
          <div className="pt-4">
            {activeView === "filters" ? (
              <div className="space-y-4">
                <label className="block">
                  <span className="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-400">Search</span>
                  <div className="mt-1.5 flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 focus-within:border-brand-blue focus-within:ring-2 focus-within:ring-brand-blue/20">
                    <HiMiniMagnifyingGlass className="h-4 w-4 text-slate-400" aria-hidden="true" />
                    <input
                      ref={searchRef}
                      type="search"
                      value={filters.search}
                      onChange={onSearchChange}
                      placeholder="Search packages, advisories, CVEs…"
                      aria-label="Search package findings"
                      className="w-full bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none"
                    />
                    {filters.search.length > 0 ? (
                      <button
                        type="button"
                        onClick={handleClearSearch}
                        aria-label="Clear search"
                        className="rounded p-0.5 text-slate-400 hover:bg-slate-100 hover:text-slate-600"
                      >
                        <HiMiniXMark className="h-3.5 w-3.5" />
                      </button>
                    ) : null}
                  </div>
                </label>
                <FilterModalContent
                  filters={filters}
                  ecosystems={ecosystems}
                  onEcosystemChange={onEcosystemChange}
                  onDecisionChange={onDecisionChange}
                  onSeverityChange={onSeverityChange}
                />
              </div>
            ) : (
              <SortModalContent sortKey={sortKey} sortDirection={sortDirection} onSortChange={onSortChange} />
            )}
          </div>
        </div>
        <div className="border-t border-slate-100 px-4 py-3">
          <div className="flex items-center justify-between gap-3">
            <button
              type="button"
              onClick={onClearFilters}
              className="text-sm font-medium text-slate-500 hover:text-slate-700"
            >
              Reset all
            </button>
            <ActionButton variant="primary" onClick={onClose}>
              Show results
            </ActionButton>
          </div>
        </div>
      </div>
    </GuardModalLayer>
  );
}

export type ActiveFilterChipProps = {
  label: string;
  onRemove: () => void;
};

export function ActiveFilterChip({ label, onRemove }: ActiveFilterChipProps) {
  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-brand-dark">
      {label}
      <button
        type="button"
        onClick={onRemove}
        aria-label={`Remove ${label}`}
        className="rounded p-0.5 text-slate-400 hover:bg-slate-100 hover:text-slate-600"
      >
        <HiMiniXMark className="h-3 w-3" />
      </button>
    </span>
  );
}

export function buildFilterSummary(
  filters: PackageWorkbenchFilters,
  sortKey: PackageWorkbenchSortKey,
  sortDirection: "asc" | "desc",
): { key: string; label: string }[] {
  const items: { key: string; label: string }[] = [];
  if (filters.ecosystem !== "all") {
    items.push({ key: "ecosystem", label: `Ecosystem: ${filters.ecosystem}` });
  }
  if (filters.decision !== "all") {
    items.push({ key: "decision", label: `Decision: ${filters.decision}` });
  }
  if (filters.severity !== "all") {
    items.push({ key: "severity", label: `Severity: ${filters.severity}` });
  }
  if (filters.search.trim().length > 0) {
    items.push({ key: "search", label: `Search: "${filters.search.trim()}"` });
  }
  if (sortKey !== "severity" || sortDirection !== "desc") {
    items.push({ key: "sort", label: `Sort: ${sortKey} ${sortDirection === "desc" ? "↓" : "↑"}` });
  }
  return items;
}
