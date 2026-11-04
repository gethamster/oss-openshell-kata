---
name: verified-delivery
description: >-
  Always apply to contributor changes. Solve the requested problem, run the
  relevant staging smoke checks and evals, decide pass or fail, and ship the fix.
  Always fast-forward on the current canonical architecture and fix forward.
  Avoid speculative engineering, unnecessary permanent tests, and repeated
  analysis or review after the evidence is sufficient.
metadata:
  always-run: "true"
  audience: "contributors"
---

# Verified Delivery

Always fast-forward. Work against the current canonical architecture and fix forward. Do
not plan for, implement, or maintain rollbacks, legacy adapters, dual protocols,
backports that preserve obsolete architectures, or speculative compatibility layers. Do
not create technical debt to accommodate old instances. Update affected consumers
coherently, remove superseded implementation paths within the authorized scope, and
verify the real current user flow.

Solve the problem and ship the fix. Overthinking, speculative redesign, duplicate
checks, and repeated reviews consume time and money without improving delivery.
Use judgment to finish the requested work, not to invent more work.

**Do not introduce delivery machinery without a current, concrete need.** Tests,
scripts, gates, holds, adapters, migration helpers, and documentation all carry
maintenance cost. Reuse what exists and remove superseded machinery with the
behavior it served. Do not replace removed tests with meta-tests, deletion
checks, a new framework, or an additional approval step.

Make the smallest complete increment work locally with relevant checks, then
push and release through the authorized path; repeat toward production. Honor
explicitly narrower requests. A local result or progress update is not task
completion when production is requested, and creates no checkpoint or approval gate.

1. **Find the concrete problem.** Read enough source and evidence to understand
   the reported failure or requested behavior. Use an existing reproduction when
   available. Do not turn a bounded bug into a repository-wide investigation.
2. **Make the smallest complete fix.** Establish the current canonical source
   revision and architecture before changing an older checkout or instance.
   Preserve the requested behavior using that architecture and its delivery path.
   Do not add an architecture, framework, abstraction, or unrelated refactor to
   make a local repair elegant.
   For pull-and-iterate work, preserve upstream structure and replay only the
   required delta. Do not migrate providers, schemas, identifiers, or installation
   machinery unless the requested behavior or a demonstrated incompatibility
   requires it. Preserve data and authorization boundaries while updating
   affected consumers together; do not preserve superseded architectures.
3. **Prove the fix efficiently.** A test is a tool, not an automatic deliverable.
   Use a temporary reproduction or focused test when it helps, then remove it
   if it adds no continuing value. Keep a regression only when it protects a
   meaningful contract or likely recurrence at reasonable maintenance cost.
   Preserve useful existing tests and required repository checks.
   For removal-only work, inspect remaining callers and run the applicable
   existing check once. Do not recreate deleted assertions elsewhere or
   repeatedly reconsider an established removal decision without new evidence.
4. **Smoke-test and evaluate.** Exercise the affected operation in the existing
   staging environment and run the relevant evals that exist. Compare observed
   behavior with the requested result. Do not build a new test framework or full
   suite for a small fix. Documentation-only work needs content and link checks;
   honor an explicit local-only or investigation-only request.
5. **Decide.** Pass when the requested behavior works, relevant smoke checks and
   evals pass, and required repository gates are satisfied. Fail for an observed
   defect or unmet requirement, not a speculative improvement. On failure, fix
   the demonstrated cause and rerun the affected check. Once passed, stop
   evaluating unchanged work and proceed to delivery.
6. **Ship.** Use the repository’s established authorized commit, review, release,
   and deployment path. Reuse the tested artifact where supported and confirm
   the intended version reached the requested destination. Do not add another
   review round, approval request, build, or test stage merely for reassurance.
   Retain mandatory human approvals and repository protections. Continue toward
   the requested release; report real blockers while independent work proceeds.
   Use clear successful tool results as evidence; investigate ambiguous outcomes
   instead of adding redundant readbacks solely to reconfirm success.

For a System release-track request, use the current owning runbook and the user's
authorized destination. See [Release-track completion](references/verification.md#release-track-completion)
for evidence reuse and resource ownership; do not create extra stages or waits.

Use [Checks and eval decisions](references/verification.md) when choosing proof,
retaining a test, or deciding whether another check is warranted. If a normal
fix is genuinely blocked by an unresolved incident or uncertain committed effect,
use [incident-recovery](../incident-recovery/SKILL.md); do not load its full
investigation procedure for every bug.

Continue within existing authorization. A missing required staging environment,
failed mandatory gate, or missing permission is a specific blocker to report,
not permission to fake a pass or bypass a protection. Complete independent work
while it is resolved. Do not re-ask for authority already granted. Before declaring an action blocked,
identify the actual user instruction, repository rule, tool denial, or enforced
policy that requires it. A configured preference alone does not establish a
mandatory gate. Use a supported task-scoped option when permitted; changing
persistent/global configuration still needs applicable authority. Report the
source and impact accurately. After a denial, follow the host's retry rules;
never change execution routes to evade it.

Keep ownership of recoverable failures. Repair the cause, reconcile the original
operation when effects are uncertain, and continue without asking the user to
retry. A status such as "held" or "retry boundary" is not a completion result.
Ask for user action only when a concrete permission, credential, or decision is
missing; name that action and continue independent work.

Report the fix, the smoke/eval result, and the shipped revision or exact blocker.
Keep it short. Follow [workspace-cleanup](../workspace-cleanup/SKILL.md) for task
resources; cleanup is not a new engineering project.
