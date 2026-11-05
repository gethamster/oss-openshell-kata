# oss-openshell-kata

Read and apply the [shared contributor guide](.agents/oss-delivery/AGENTS.md)
from [oss-delivery](https://github.com/gethamster/oss-delivery), pinned at
`4dd3e7aa912771f14ddb36352b579aaf58b95c93` in [.agents/oss-delivery/lock.json](.agents/oss-delivery/lock.json).
The complete pack is available locally in `.agents/skills/`; `.claude/skills/`
contains regular-file entrypoints to the same instructions.

Always apply [verified-delivery](.agents/skills/verified-delivery/SKILL.md) and
[workspace-cleanup](.agents/skills/workspace-cleanup/SKILL.md). Solve the requested
problem, use proportionate proof, run relevant existing staging smoke/evals,
and ship once the outcome and actual repository gates pass. Reuse valid evidence.
Temporary repro tests may be removed when they add no continuing value. Do not
add coverage quotas, mandatory test-first work, independent review, full-suite
reruns, or another approval round by default. Carry existing user authorization
through delivery; ask only for a genuinely missing decision or permission.

These notes and nested contributor files add repository facts and affected
commands, not extra process gates. Product authorization and data boundaries
remain part of correct behavior. Runtime-agent instructions describe agents
running inside the product and do not override this contributor workflow.
Update shared guidance in oss-delivery, then sync the pinned copy; do not fork
its managed files locally.

## Repository scope

This repository owns the Rust external compute adapter and host enforcement for
Kata VMs. Keep the supported upstream OpenShell protocol compatible. Treat the
guest VM, its root user, and nested containers as untrusted; enforce resource,
filesystem-transfer, and network limits outside the guest. Never broaden an
operator policy to make a smoke check succeed.

Read the relevant sections of [the enforcement contract](docs/ENFORCEMENT_CONTRACT.md)
when changing those boundaries, and [the hosted profile](docs/HOSTED.md) for its
specific capabilities. Preserve upstream licenses and protocol source identities.
Do not commit private runtime artifacts, keys, guest data, or local VM state.

## Relevant checks and delivery

[CI](.github/workflows/ci.yml) defines Rust, protocol-checksum, and hosted-fence
checks. Use focused local checks for the affected code and reuse valid CI results.
A changed enforcement boundary needs a smoke/eval of that boundary in the target
profile; it does not require requalifying every platform for an unrelated fix.
Guidance-only changes need content/link checks, not a new VM or binary release.

Contributor-only changes are excluded from application CI. Code and mixed changes
keep the existing checks.
