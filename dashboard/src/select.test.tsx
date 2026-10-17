import { renderToStaticMarkup } from "react-dom/server";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { Select } from "./select";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

const srcRoot = fileURLToPath(new URL(".", import.meta.url));

function* sourceFiles(dir: string): Generator<string> {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      yield* sourceFiles(path);
    } else if (/\.(ts|tsx)$/.test(entry) && !/\.test\.(ts|tsx)$/.test(entry) && entry !== "select.tsx") {
      yield path;
    }
  }
}

for (const file of sourceFiles(srcRoot)) {
  assert(
    !/<select[\s>]/.test(readFileSync(file, "utf8")),
    `native <select> must not be used in ${file} — use the styled Select from ./select, whose popup renders consistently on every OS`,
  );
}

const noop = () => undefined;
const OPTIONS = [
  { value: "all", label: "All decisions" },
  { value: "block", label: "Stopped" },
  { value: "allow", label: "Allowed" },
];

const markup = renderToStaticMarkup(
  <Select value="block" options={OPTIONS} onValueChange={noop} aria-label="Decision filter" />,
);

assert(markup.includes('role="combobox"'), "the trigger announces itself as a combobox");
assert(markup.includes('aria-haspopup="listbox"'), "the trigger points at a listbox popup");
assert(markup.includes('aria-expanded="false"'), "the popup starts closed");
assert(markup.includes(">Stopped<"), "the trigger shows the selected option's label");
assert(markup.includes('data-select-value="block"'), "the trigger carries the selected value for tests");
assert(markup.includes('aria-label="Decision filter"'), "the accessible name reaches the trigger");
assert(!markup.includes('role="option"'), "options render only while the popup is open");
assert(markup.includes("<svg"), "the trigger carries a chevron affordance");

const unknownValue = renderToStaticMarkup(
  <Select value="mystery" options={OPTIONS} onValueChange={noop} aria-label="Decision filter" />,
);
assert(unknownValue.includes(">mystery<"), "a value outside the option list still renders as the label");

const described = renderToStaticMarkup(
  <Select value="all" options={OPTIONS} onValueChange={noop} aria-label="Decision filter" describedBy="filter-help" />,
);
assert(described.includes('aria-describedby="filter-help"'), "describedBy wires the description to the trigger");

const withId = renderToStaticMarkup(
  <Select value="all" options={OPTIONS} onValueChange={noop} id="my-select" aria-label="Decision filter" />,
);
assert(withId.includes('id="my-select"'), "an external label can point at the trigger by id");

const disabled = renderToStaticMarkup(
  <Select value="all" options={OPTIONS} onValueChange={noop} disabled aria-label="Decision filter" />,
);
assert(disabled.includes("disabled"), "a disabled select renders its trigger disabled");

const noOptions = renderToStaticMarkup(
  <Select value="" options={[]} onValueChange={noop} aria-label="Empty filter" />,
);
assert(noOptions.includes("disabled"), "a select with no options stays inert instead of opening an empty popup");
assert(!noOptions.includes('role="combobox"'), "the inert empty state does not promise a popup");
