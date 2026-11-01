# OSS Delivery

This repository is the system of record for shared instructions, skills, and
references for people and coding agents developing, testing, releasing, and
maintaining Hamster’s OSS software. Product code, deployment configuration,
runtime identifiers, and authoritative product data stay in their owning
repositories.

Runtime agent prompts and skills define behavior inside the product and belong
in the owning product repository. Do not treat them as contributor guidance
merely because their names or content overlap. Any adaptation for contributors
must be explicitly selected and reviewed for that audience.

## Guidance and ownership

- `../skills/` contains the maintained skills for use here and in consuming
  repositories. Keep each skill self-contained, with its supporting references
  and required license notices.
- `resources/` contains reference material and recorded upstream imports.
  Preserve the pinned `resources/beautiful-rust/` snapshot unchanged; make
  skill changes in `../skills/`. Keep skill text focused on actionable
  instructions; do not add adaptation histories or original-file records.
- Write shared instructions for roles such as the user, operator, or maintainer
  rather than named individuals. Keep them applicable across repositories.
  Build commands, infrastructure identifiers, service boundaries, and deployment
  gates belong in the owning repository’s instructions.
- Follow the user’s requested scope and the applicable instructions of the
  repository being changed. A skill does not grant permissions or authorize
  changes in other repositories. Preserve unrelated work.

## Delivery

Always fast-forward. Work against the current canonical architecture and fix forward. Do
not plan for, implement, or maintain rollbacks, legacy adapters, dual protocols,
backports that preserve obsolete architectures, or speculative compatibility layers. Do
not create technical debt to accommodate old instances. Update affected consumers
coherently, remove superseded implementation paths within the authorized scope, and
verify the real current user flow.

Drive changes through the shortest authorized loop: make the smallest complete
increment work locally with relevant checks, push, release; repeat. Production is
the goal unless the user specifies a narrower endpoint. Preserve upstream as the
foundation. Status updates and local usability are progress, not extra gates or
stopping points. Report real blockers promptly and keep independent work moving.

Always apply [verified-delivery](../skills/verified-delivery/SKILL.md): solve
the requested problem, run relevant staging smoke/evals and required checks,
decide pass or fail, and ship. Do not turn a bounded fix into speculative
engineering, permanent test infrastructure, or repeated review loops. Honor
narrower requests and existing protections; do not ask again for granted authority.

Local development is authorized without additional approval. Create and iterate
installation-owned local services, isolated test databases, test users and agent
principals, and disposable development credentials as needed to build and verify
the system. This includes local configuration, restarts, token exchange, and
credential rotation within those development resources. Preserve shared local
state and other contributors' work, and keep credentials out of logs and Git.
This standing authorization does not extend to production credentials, remote
customer resources, spending money, or irreversible deletion of existing data.

Verified-delivery governs the amount of process across this pack. Specialist skills
and source digests guide the affected work; they do not add tests, reviews, CI jobs,
coverage targets, or redesign by default. Read only relevant references, reuse valid
evidence, and stop checking unchanged work once the requested outcome and actual
repository gates pass. Required protections and explicit user criteria still apply.

Use [incident-recovery](../skills/incident-recovery/SKILL.md) only when an
unresolved incident or uncertain committed effect blocks a normal fix. It is
not an extra stage for every repair.

Always apply [workspace-cleanup](../skills/workspace-cleanup/SKILL.md) at
contributor handoff or completion and when task-owned resources become
disposable. Preserve active work, runtime state, and required evidence; no
resources to retire means no cleanup action.

Use [work-coordination](../skills/work-coordination/SKILL.md) when assigning
parallel work, coordinating shared services, or handing work between contributors.
It delegates resource retirement to workspace-cleanup.

Use [release-efficiency](../skills/release-efficiency/SKILL.md) when changing
build or release pipelines or investigating delivery delays.

Use [local-verification](../skills/local-verification/SKILL.md) when changing
or diagnosing running local services, their configuration and state, or the user
journeys they support.

## Documentation

Use [domain-language](../skills/domain-language/SKILL.md) when naming or
editing domain terms in prose or identifiers. Preserve established meanings and
update published identifiers and affected consumers coherently on the current architecture.

Use [technical-documentation](../skills/technical-documentation/SKILL.md)
when documenting or changing service contracts, architecture, or operational
runbooks. Use each repository’s owning sources and existing documentation tools.

## Interfaces

Use [interface-design](../skills/interface-design/SKILL.md) when designing,
implementing, or reviewing product interfaces. It carries Studio tokens and
rounded-control references and applies to prototypes as well as production UI.

## Rust skills

- Use [rust-best-practices](../skills/rust-best-practices/SKILL.md) when writing or changing Rust.
- Use [rust-review](../skills/rust-review/SKILL.md) for Rust reviews.
- Use [rust-port](../skills/rust-port/SKILL.md) when porting code to Rust.

Read the relevant skill and follow its links to supporting references as needed.

## Security and verification

Never commit credentials, secret values, private runtime configuration,
Terraform/OpenTofu state or tfvars, runtime databases, or private transcripts.

Use only the Google Cloud CLI for Google Cloud access, with an explicit project
and exact Kubernetes context when applicable. If authentication expires, ask
the user or responsible operator to run `gcloud auth login` in their terminal;
continue independent work.

Run the owning repository’s required checks and follow its review and release
process. For guidance changes here, validate skill metadata, referenced files,
relative links, and license preservation. Verify the affected behavior when
changing executable helpers or examples. Report what was checked and what
remains unverified; a successful build alone does not prove a working deployment.
