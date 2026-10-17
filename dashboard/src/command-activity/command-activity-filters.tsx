import { useCallback, useMemo } from "react";

import type { CommandActivityFilters } from "./command-activity-state";
import { safeEvidenceId } from "./command-activity-presenters";
import type { CommandActivityAnalytics, CommandExtensionsPage } from "./command-activity-types";
import { Select, type SelectOption } from "../select";

interface FilterOption {
  label: string;
  value: string;
}

function preserveActiveOption(options: FilterOption[], activeValue: string | null): FilterOption[] {
  if (activeValue === null || options.some((option) => option.value === activeValue)) return options;
  const label = safeEvidenceId(activeValue);
  if (label === "Unavailable") return options;
  return [...options, { label, value: activeValue }];
}

function SelectField(props: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: readonly SelectOption[];
}) {
  return (
    <label className="min-w-0 text-xs font-medium text-slate-600">
      <span className="mb-1 block">{props.label}</span>
      <Select
        value={props.value}
        onValueChange={props.onChange}
        className="w-full"
        options={props.options}
      />
    </label>
  );
}

export function CommandActivityFiltersPanel(props: {
  filters: CommandActivityFilters;
  extensions: CommandExtensionsPage | null;
  analytics: CommandActivityAnalytics | null;
  lockedHarness: string | null;
  resultCount: number | null;
  onChange: (patch: Partial<CommandActivityFilters>) => void;
}) {
  let interactionValue = "";
  if (props.filters.prompted === true) interactionValue = "prompted";
  if (props.filters.prompted === false) interactionValue = "not_prompted";
  const harnesses = useMemo(
    () => preserveActiveOption(
      props.analytics?.dimensions.harness
        .map((bucket) => safeEvidenceId(bucket.value))
        .filter((value) => value !== "Unavailable")
        .map((value) => ({ label: value, value })) ?? [],
      props.filters.harness,
    ),
    [props.analytics, props.filters.harness],
  );
  const selectedExtension = props.extensions?.items.find(
    (extension) => extension.extension_id === props.filters.extension_id,
  );
  const extensions = useMemo(
    () => preserveActiveOption(
      props.extensions?.items.map((extension) => ({ label: extension.name, value: extension.extension_id })) ?? [],
      props.filters.extension_id,
    ),
    [props.extensions, props.filters.extension_id],
  );
  const rules = useMemo(
    () => preserveActiveOption(
      selectedExtension?.rules.map((rule) => ({ label: rule.title, value: rule.rule_id })) ?? [],
      props.filters.rule_id,
    ),
    [props.filters.rule_id, selectedExtension],
  );

  const handleHarness = useCallback(
    (value: string) => props.onChange({ harness: value || null }),
    [props.onChange],
  );
  const handleExtension = useCallback(
    (value: string) => props.onChange({ extension_id: value || null, rule_id: null }),
    [props.onChange],
  );
  const handleRule = useCallback(
    (value: string) => props.onChange({ rule_id: value || null }),
    [props.onChange],
  );
  const handleExecution = useCallback(
    (value: string) => props.onChange({ execution_status: (value || null) as CommandActivityFilters["execution_status"] }),
    [props.onChange],
  );
  const handleProof = useCallback(
    (value: string) => props.onChange({ proof_level: (value || null) as CommandActivityFilters["proof_level"] }),
    [props.onChange],
  );
  const handlePrompted = useCallback(
    (value: string) => {
      let prompted: boolean | null = null;
      if (value === "prompted") prompted = true;
      if (value === "not_prompted") prompted = false;
      props.onChange({ prompted });
    },
    [props.onChange],
  );
  const handleReuse = useCallback(
    (value: string) => props.onChange({ approval_reuse_status: (value || null) as CommandActivityFilters["approval_reuse_status"] }),
    [props.onChange],
  );

  return (
    <section aria-label="Command activity filters" className="rounded-lg border border-slate-200 bg-slate-50/60 p-3">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7">
        {props.lockedHarness === null ? (
          <SelectField
            label="App"
            value={props.filters.harness ?? ""}
            onChange={handleHarness}
            options={[
              { value: "", label: "All apps" },
              ...harnesses.map((harness) => ({ value: harness.value, label: harness.label })),
            ]}
          />
        ) : null}
        <SelectField
          label="Extension"
          value={props.filters.extension_id ?? ""}
          onChange={handleExtension}
          options={[
            { value: "", label: "All extensions" },
            ...extensions.map((extension) => ({ value: extension.value, label: extension.label })),
          ]}
        />
        <SelectField
          label="Rule"
          value={props.filters.rule_id ?? ""}
          onChange={handleRule}
          options={[
            { value: "", label: "All rules" },
            ...rules.map((rule) => ({ value: rule.value, label: rule.label })),
          ]}
        />
        <SelectField
          label="Run result"
          value={props.filters.execution_status ?? ""}
          onChange={handleExecution}
          options={[
            { value: "", label: "All run results" },
            { value: "attempted", label: "Attempt recorded" },
            { value: "prevented", label: "Prevented" },
            { value: "allowed_unconfirmed", label: "Result not recorded" },
            { value: "confirmed_success", label: "Confirmed success" },
            { value: "confirmed_failure", label: "Confirmed failure" },
            { value: "unpaired_post", label: "Unpaired post proof" },
          ]}
        />
        <SelectField
          label="Proof source"
          value={props.filters.proof_level ?? ""}
          onChange={handleProof}
          options={[
            { value: "", label: "All proof sources" },
            { value: "pre_hook", label: "Pre-execution only" },
            { value: "post_hook", label: "Post-execution" },
            { value: "unpaired_post", label: "Unpaired post proof" },
          ]}
        />
        <SelectField
          label="Interaction"
          value={interactionValue}
          onChange={handlePrompted}
          options={[
            { value: "", label: "All interactions" },
            { value: "prompted", label: "Review requested" },
            { value: "not_prompted", label: "No review prompt" },
          ]}
        />
        <SelectField
          label="Authorization reuse"
          value={props.filters.approval_reuse_status ?? ""}
          onChange={handleReuse}
          options={[
            { value: "", label: "All reuse states" },
            { value: "accepted", label: "Accepted" },
            { value: "rejected", label: "Rejected" },
            { value: "not-applicable", label: "Not applicable" },
          ]}
        />
      </div>
      <p className="mt-2 min-h-5 text-xs text-slate-500" aria-live="polite">
        {props.resultCount === null ? "Loading command activity…" : `${props.resultCount.toLocaleString()} records on this page`}
      </p>
    </section>
  );
}
