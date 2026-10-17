import {
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";
import { HiMiniCheck, HiMiniChevronDown } from "react-icons/hi2";

export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

const MAX_LIST_HEIGHT = 240; // px — keeps long catalogs to a scannable column
const VIEWPORT_MARGIN = 8; // px — the popup never hugs the window edge
const TYPEAHEAD_RESET_MS = 500;

// Layout timing matters when the popup first opens (scroll the active option
// into view before first paint), but the server render must not warn.
const useIsomorphicLayoutEffect = typeof document === "undefined" ? useEffect : useLayoutEffect;

interface SelectProps {
  value: string;
  options: readonly SelectOption[];
  onValueChange: (value: string) => void;
  /** Accessible name when no visible label is associated with the control. */
  "aria-label"?: string;
  "aria-labelledby"?: string;
  /** id of an element describing this control, mirroring aria-describedby. */
  describedBy?: string;
  disabled?: boolean;
  /** Associates an external <label> with the trigger, like <select id>. */
  id?: string;
  /** "sm" matches compact filter toolbars; "md" (default) matches form rows. */
  size?: "sm" | "md";
  /** Extra classes for the trigger, e.g. width utilities. */
  className?: string;
  testId?: string;
}

const TRIGGER_CLASSES: Record<"sm" | "md", string> = {
  sm: "min-h-8 gap-1 rounded-lg px-2 text-xs font-medium",
  md: "min-h-11 gap-1.5 rounded-xl px-3 text-sm",
};

/**
 * A styled replacement for native <select>. The trigger keeps keyboard focus
 * while the popup is open and drives the highlighted option through
 * aria-activedescendant, so screen readers announce the moving selection the
 * way they do a native dropdown. The popup portals to document.body with fixed
 * positioning, so no overflow-hidden ancestor can clip it.
 */
export function Select(props: SelectProps) {
  const {
    value,
    options,
    onValueChange,
    disabled = false,
    size = "md",
    className = "",
    testId,
    describedBy,
    id,
  } = props;
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const [popupStyle, setPopupStyle] = useState<{
    left: number;
    top: number;
    minWidth: number;
    above: boolean;
  } | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const popupRef = useRef<HTMLDivElement | null>(null);
  const activeOptionRef = useRef<HTMLDivElement | null>(null);
  const typeaheadRef = useRef({ buffer: "", expiresAt: 0 });
  const listboxId = useId();
  const enabledIndexes = useMemo(
    () =>
      options
        .map((option, index) => (option.disabled ? -1 : index))
        .filter((index) => index >= 0),
    [options],
  );
  const selectedIndex = options.findIndex((option) => option.value === value);
  const selected = selectedIndex >= 0 ? options[selectedIndex] : undefined;
  const selectedLabel = selected?.label ?? value;

  const commit = useCallback(
    (index: number) => {
      const option = options[index];
      if (!option || option.disabled) return;
      if (option.value !== value) onValueChange(option.value);
      setOpen(false);
      triggerRef.current?.focus();
    },
    [onValueChange, options, value],
  );

  const placePopup = useCallback(() => {
    const trigger = triggerRef.current;
    if (!trigger) return;
    const rect = trigger.getBoundingClientRect();
    const spaceBelow = window.innerHeight - rect.bottom;
    const above = spaceBelow < Math.min(MAX_LIST_HEIGHT, 160) && rect.top > spaceBelow;
    const left = Math.min(
      Math.max(VIEWPORT_MARGIN, rect.left),
      window.innerWidth - VIEWPORT_MARGIN - Math.min(rect.width, window.innerWidth - VIEWPORT_MARGIN * 2),
    );
    setPopupStyle({
      left,
      top: above ? rect.top - VIEWPORT_MARGIN : rect.bottom + 4,
      minWidth: rect.width,
      above,
    });
  }, []);

  const openPopup = useCallback(() => {
    if (disabled || options.length === 0) return;
    const start = selectedIndex >= 0 ? selectedIndex : enabledIndexes[0] ?? 0;
    setActiveIndex(start);
    placePopup();
    setOpen(true);
  }, [disabled, enabledIndexes, options.length, placePopup, selectedIndex]);

  const moveActive = useCallback(
    (step: 1 | -1, from: number) => {
      if (enabledIndexes.length === 0) return;
      const position = enabledIndexes.indexOf(from);
      const next =
        position === -1
          ? step === 1
            ? enabledIndexes[0]
            : enabledIndexes[enabledIndexes.length - 1]
          : enabledIndexes[(position + step + enabledIndexes.length) % enabledIndexes.length];
      setActiveIndex(next);
    },
    [enabledIndexes],
  );

  const typeahead = useCallback(
    (character: string) => {
      const now = Date.now();
      const state = typeaheadRef.current;
      state.buffer = (now < state.expiresAt ? state.buffer : "") + character.toLowerCase();
      state.expiresAt = now + TYPEAHEAD_RESET_MS;
      const match = options.findIndex(
        (option) => !option.disabled && option.label.toLowerCase().startsWith(state.buffer),
      );
      if (match >= 0) setActiveIndex(match);
    },
    [options],
  );

  const handleTriggerKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLButtonElement>) => {
      if (!open) {
        if (event.key === "ArrowDown" || event.key === "ArrowUp" || event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          openPopup();
        }
        return;
      }
      if (event.key === "ArrowDown") {
        event.preventDefault();
        moveActive(1, activeIndex);
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        moveActive(-1, activeIndex);
      } else if (event.key === "Home") {
        event.preventDefault();
        if (enabledIndexes.length > 0) setActiveIndex(enabledIndexes[0]);
      } else if (event.key === "End") {
        event.preventDefault();
        if (enabledIndexes.length > 0) setActiveIndex(enabledIndexes[enabledIndexes.length - 1]);
      } else if (event.key === "Enter") {
        event.preventDefault();
        commit(activeIndex);
      } else if (event.key === " ") {
        event.preventDefault();
        commit(activeIndex);
      } else if (event.key === "Escape") {
        event.preventDefault();
        setOpen(false);
        triggerRef.current?.focus();
      } else if (event.key === "Tab") {
        setOpen(false);
      } else if (event.key.length === 1 && !event.metaKey && !event.ctrlKey && !event.altKey) {
        typeahead(event.key);
      }
    },
    [activeIndex, commit, enabledIndexes, moveActive, open, openPopup, typeahead],
  );

  // Focus lives on the trigger the whole time; only a real focus handoff
  // (Tab, clicking elsewhere) closes the popup through blur.
  const handleTriggerBlur = useCallback((event: React.FocusEvent<HTMLButtonElement>) => {
    const next = event.relatedTarget;
    if (next instanceof Node && popupRef.current?.contains(next)) return;
    setOpen(false);
  }, []);

  // A scroll anywhere outside the popup would detach it from its anchor.
  useEffect(() => {
    if (!open) return;
    const handleScroll = (event: Event) => {
      if (event.target instanceof Node && popupRef.current?.contains(event.target)) return;
      setOpen(false);
    };
    window.addEventListener("scroll", handleScroll, true);
    window.addEventListener("resize", handleScroll);
    return () => {
      window.removeEventListener("scroll", handleScroll, true);
      window.removeEventListener("resize", handleScroll);
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const handlePointerDown = (event: PointerEvent) => {
      const target = event.target;
      if (
        target instanceof Node &&
        (popupRef.current?.contains(target) || triggerRef.current?.contains(target))
      ) {
        return;
      }
      setOpen(false);
    };
    document.addEventListener("pointerdown", handlePointerDown);
    return () => document.removeEventListener("pointerdown", handlePointerDown);
  }, [open]);

  useIsomorphicLayoutEffect(() => {
    if (!open) return;
    activeOptionRef.current?.scrollIntoView({ block: "nearest" });
  }, [activeIndex, open]);

  if (options.length === 0 && !open) {
    // A select with no choices is inert rather than an empty popup.
    return (
      <button
        type="button"
        ref={triggerRef}
        id={id}
        disabled
        aria-label={props["aria-label"]}
        aria-labelledby={props["aria-labelledby"]}
        aria-describedby={describedBy}
        data-testid={testId}
        data-select-value={value}
        className={`${TRIGGER_CLASSES[size]} inline-flex max-w-full items-center border border-slate-200 bg-white text-brand-dark disabled:cursor-not-allowed disabled:opacity-60 ${className}`}
      >
        <span className="truncate">{selectedLabel || "—"}</span>
      </button>
    );
  }

  return (
    <>
      <button
        type="button"
        ref={triggerRef}
        id={id}
        role="combobox"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listboxId : undefined}
        aria-activedescendant={open ? `${listboxId}-option-${activeIndex}` : undefined}
        aria-label={props["aria-label"]}
        aria-labelledby={props["aria-labelledby"]}
        aria-describedby={describedBy}
        disabled={disabled}
        data-testid={testId}
        data-select-value={value}
        onBlur={handleTriggerBlur}
        onClick={() => (open ? setOpen(false) : openPopup())}
        onKeyDown={handleTriggerKeyDown}
        className={`${TRIGGER_CLASSES[size]} inline-flex max-w-full items-center border border-slate-200 bg-white text-brand-dark transition-colors hover:border-brand-blue/55 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue disabled:cursor-not-allowed disabled:opacity-60 aria-expanded:border-brand-blue motion-reduce:transition-none ${className}`}
      >
        <span className="truncate">{selectedLabel || "—"}</span>
        <HiMiniChevronDown
          className={`ml-auto size-3.5 shrink-0 text-brand-dark/50 transition-transform duration-150 motion-reduce:transition-none ${open ? "rotate-180" : ""}`}
          aria-hidden="true"
        />
      </button>
      {open && popupStyle
        ? createPortal(
            <div
              ref={popupRef}
              role="listbox"
              id={listboxId}
              aria-label={props["aria-label"]}
              aria-labelledby={props["aria-labelledby"]}
              tabIndex={-1}
              className="fixed z-50 overflow-y-auto overscroll-contain rounded-xl border border-[rgba(63,65,116,0.12)] bg-white p-1 shadow-[0_12px_32px_rgba(63,65,116,0.16)]"
              style={{
                left: popupStyle.left,
                top: popupStyle.above ? undefined : popupStyle.top,
                bottom: popupStyle.above ? window.innerHeight - popupStyle.top : undefined,
                minWidth: popupStyle.minWidth,
                maxHeight: MAX_LIST_HEIGHT,
              }}
            >
              {options.map((option, index) => {
                const active = index === activeIndex;
                const isSelected = index === selectedIndex;
                return (
                  <div
                    key={option.value}
                    ref={active ? activeOptionRef : undefined}
                    role="option"
                    id={`${listboxId}-option-${index}`}
                    aria-selected={isSelected}
                    aria-disabled={option.disabled || undefined}
                    data-active={active || undefined}
                    onPointerMove={() => setActiveIndex(index)}
                    // Keep focus on the trigger: letting the browser move it
                    // would blur-close the popup before the click commits.
                    onMouseDown={(event) => event.preventDefault()}
                    onClick={() => commit(index)}
                    className={`flex min-h-9 cursor-pointer items-center justify-between gap-3 rounded-lg px-2.5 text-sm text-brand-dark aria-disabled:cursor-not-allowed aria-disabled:opacity-45 ${
                      active ? "bg-brand-blue/10" : ""
                    } ${isSelected ? "font-semibold" : ""}`}
                  >
                    <span className="min-w-0 truncate py-1.5">{option.label}</span>
                    {isSelected ? (
                      <HiMiniCheck className="size-4 shrink-0 text-brand-blue" aria-hidden="true" />
                    ) : null}
                  </div>
                );
              })}
            </div>,
            document.body,
          )
        : null}
    </>
  );
}
