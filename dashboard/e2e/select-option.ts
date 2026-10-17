import { expect, type Page } from "@playwright/test";

/**
 * Drives the dashboard's custom Select (role="combobox") the way a person
 * does: open the popup, then click the option by its visible label.
 */
export async function chooseSelectOption(
  page: Page,
  name: string,
  optionLabel: string,
  options: { exact?: boolean } = {},
): Promise<void> {
  const trigger = page.getByRole("combobox", { name, exact: options.exact ?? true });
  await trigger.click();
  await page.getByRole("option", { name: optionLabel, exact: options.exact ?? true }).click();
  await expect(trigger).toHaveAttribute("aria-expanded", "false");
}
