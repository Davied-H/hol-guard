import { HiMiniInformationCircle } from "react-icons/hi2";

import { bulkLineCommand } from "./approval-retry-guidance";
import type { GuardApprovalRequest } from "./guard-types";
import { LoggedActionPanel } from "./logged-action-panel";

/**
 * Shown in place of Approve when no decision can let the agent run the command
 * (`approvalCannotUnlock`): the user can still run it in their own terminal.
 */
export function ReviewRunYourself(props: { item: GuardApprovalRequest; harnessName: string }) {
  const command = bulkLineCommand(props.item);
  return (
    <section
      aria-label="Run this yourself"
      data-testid="review-run-yourself"
      className="mt-5 rounded-xl border border-brand-blue/25 bg-brand-blue/[0.04] p-4"
    >
      <div className="flex items-start gap-3">
        <HiMiniInformationCircle className="mt-0.5 h-5 w-5 shrink-0 text-brand-blue" aria-hidden="true" />
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-semibold text-brand-dark">Run this yourself</h3>
          <p className="mt-1 text-sm leading-6 text-brand-dark">
            Guard cannot let {props.harnessName} run this command, even if you approve it, so
            approving would change nothing and {props.harnessName} would be blocked again. Run it
            in your own terminal if you want it done, or keep it blocked.
          </p>
        </div>
      </div>
      {command !== null ? (
        <div className="mt-3">
          <LoggedActionPanel label="Command" text={command} />
        </div>
      ) : null}
    </section>
  );
}
