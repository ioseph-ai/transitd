# Security policy

transitd is a network tool that runs with privileged access on routers. We
take security reports seriously and would rather hear about a problem early
than read about it later.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — do not open a public
issue, and do not post details in a discussion, chat, or social media.

Use GitHub **Private Vulnerability Reporting** for this repository:

1. Open the repository's [Security tab](https://github.com/ioseph-ai/transitd/security).
2. Click **Report a vulnerability** (this opens a private advisory draft
   visible only to you and the maintainers).
3. Describe the issue: affected version/commit, the affected component, the
   impact you believe it has, and — if you can — a minimal reproduction.

If the "Report a vulnerability" button is not available, Private Vulnerability
Reporting has not been enabled on the repository yet; in that case open a
minimal public issue asking the maintainer to enable it (or to provide a
private channel) **without including vulnerability details**.

### What to expect

- **Acknowledgement:** within 7 days.
- **Triage:** an initial assessment (severity, whether we consider it in
  scope, whether a fix is feasible) within 14 days.
- **Disclosure:** we aim to publish a fix and a GitHub Security Advisory,
  crediting you unless you prefer otherwise. We will coordinate a disclosure
  date with you; if a fix is not feasible quickly we will say so and agree on
  next steps rather than let the report sit silently.

Please give us a reasonable window to ship a fix before public disclosure.
There is no bug-bounty program and no payment is offered.

## Supported versions

transitd is **pre-1.0** and has not made a stable release. Only the **latest
release tag** (and the tip of `master`) is supported. Older tags are not
maintained; if you are on anything else, reproduce against the latest tag
before reporting.

## Scope

### In scope

- The **runtime agent** that runs on routers (`transitd`), including:
  - its configuration parsing and validation,
  - the gossip/mesh protocol it speaks (membership, state exchange, and how
    it treats peer-supplied data),
  - the `transitctl` control surface,
  - the decision/actuation path and its safety mechanisms (quorum,
    hysteresis, rate limits, audit log),
  - any parsing of untrusted input (peer gossip payloads, CLI input, FRR
    JSON output it consumes).
- How the agent handles the **gossip key** — see the trust model below.

### Out of scope

- Bugs in FRR, VyOS, WireGuard, the Linux kernel, or the underlying mesh that
  transitd does not make worse. Report those upstream.
- Anything requiring an attacker to already have root on the router, or
  write access to the agent's configuration file or its process memory.
- Misconfiguration that leaves the gossip key world-readable, unless transitd
  itself caused or encouraged it.
- Denial of service by an authenticated mesh member that merely makes the
  agent *freeze* (fail safe) rather than take a harmful action.
- The CI/release tooling and dependencies, unless the issue has a concrete
  runtime impact. (Dependency vulnerabilities: Dependabot alerts and
  `govulncheck` cover those.)

## Trust model — read this before reporting

These points are part of transitd's documented design; a report that just
points them out is not a vulnerability:

- **The gossip key is root-equivalent on the routing plane.** Gossip is
  encrypted with a shared key (memberlist `SecretKey`). Anyone who holds that
  key is a trusted member of the mesh and can influence the agent's merged
  view of transit health, and therefore the decisions it makes. Treat the
  gossip key like an SSH key: rotate it, keep it off-world-readable storage,
  and never put it in a config-management checkout or a support bundle.
- **vtysh access is not a privilege boundary.** The agent needs the FRR
  `vtysh` sockets and drives them to apply runtime changes (route-map
  local-preference, soft clears). `vtysh` access is equivalent to the ability
  to change routing preference — do not assume it is a lower privilege tier
  than the gossip key.
- **The mesh is assumed trusted.** transitd assumes the network the agents
  gossip over (typically WireGuard or an IXP/routed LAN) is itself
  authenticated and encrypted. Attacks that require an on-path attacker
  *inside* that assumed-trusted mesh are generally not in scope, though we
  want to hear about anything that makes a compromise of one member
  escalate further than the trust model already allows.

Because the gossip key is root-equivalent, **key handling is explicitly in
scope**: if you find a way transitd leaks the key, logs it, exposes it over
the metrics endpoint, or fails to zero it where it should, that is a
vulnerability and we want the report.

## Hardening guidance

- Run the agent only on hosts that already have `vtysh` access locked down.
- Keep the gossip key out of version control, logs, and support bundles.
- Enable Private Vulnerability Reporting (see above) on your own forks.

## Example values

Any configuration, log, or topology in this repository or in issues uses
documentation ranges only (`2001:db8::/32`, `192.0.2.0/24`,
`198.51.100.0/24`, AS 64496–64511). If you see real addresses or ASNs in a
report or a pull request, that is a mistake — say so (privately, for a
security report) and we will scrub it.
