# Security Policy

Thanks for helping keep DroneAware Network™ and its users safe. This policy
covers the DroneAware platform end-to-end — the node firmware shipped from
this repository, the server-side API at `api.droneaware.io`, the web frontend
at `droneaware.io`, and related infrastructure.

## Supported Versions

DroneAware node firmware is distributed through this repository as the
canonical install source. Security patches land in the latest release tagged
`latest` on GitHub. We strongly encourage all node operators to keep their
firmware current.

| Version           | Supported          | Notes                                                        |
| ----------------- | ------------------ | ------------------------------------------------------------ |
| v1.1.x (current)  | :white_check_mark: | Active development; all security patches land here           |
| v1.0.x (legacy)   | :x:                | Run `sudo droneaware update` on your node to move to v1.1.x  |
| < v1.0            | :x:                | Re-run the installer from droneaware.io/enroll.html          |

The server-side components (api.droneaware.io, droneaware.io) always run
the latest revision and are not versioned for users — patches are applied
continuously.

## Reporting a Vulnerability

**Please do not file public GitHub issues for security vulnerabilities** —
public reports give attackers a window to exploit before we can patch.

Use **GitHub Private Vulnerability Reporting** to send your report securely:

→ **[Submit a private report](https://github.com/fduflyer/DroneAware-Node-Releases/security/advisories/new)**

This works for any DroneAware vulnerability, not just bugs in this specific
repository's code — server-side API, web frontend, infrastructure, and
node firmware are all triaged through this channel.

If you cannot use GitHub for any reason, email **support@droneaware.io** as
a fallback. GitHub is strongly preferred because it gives both of us an
auditable timeline, structured collaboration, and can lead to a published
CVE if appropriate.

Include in your report:

- A description of the issue and its potential impact
- Steps to reproduce, ideally with proof-of-concept code or commands
- The affected component (node firmware, server API, frontend, infrastructure)
- Any relevant version numbers, commit hashes, or timestamps
- Your name / handle for acknowledgment (optional but appreciated)

### What to expect

- **Acknowledgment** within **72 hours** of report
- **Triage and severity assessment** within **7 days**, communicated back to you
- **Fix or mitigation** within **30 days** for High/Critical issues; longer
  timelines for Low/Medium with status updates every two weeks
- **Coordinated disclosure** - we'll work with you on timing; the default
  embargo is until a fix is deployed plus 7 days for users to update

### What is in scope

- Authentication and authorization flaws in the server API
- Injection attacks (SQL, XSS, command, etc.) on droneaware.io / api.droneaware.io
- Cryptographic weaknesses in session, token, or password handling
- Vulnerabilities in the node firmware installer or feeder code
- Exposure of personally identifiable information beyond what the privacy
  policy permits (see https://droneaware.io/legal.html)
- Privilege escalation paths between node, owner, and admin roles
- Supply-chain risks in dependencies we control

### What is out of scope

- **Remote ID broadcast spoofing.** The FAA Remote ID protocol is
  unauthenticated by design. Reports demonstrating that spoofed RID
  broadcasts can be ingested are not vulnerabilities, they are inherent to
  the protocol. We are interested in research on *detection* of such spoofs,
  but that lives in a separate private channel (contact us first).
- **Denial-of-service tests against production infrastructure.**
- Social engineering of DroneAware staff or community members
- Physical attacks against node hardware (the receivers are intentionally
  passive RF listeners with no offensive capability)
- Findings from automated scanners with no demonstrated impact
- Vulnerabilities in third-party dependencies for which a fix has already
  been published — please report those upstream

### Recognition

Researchers who follow this policy and report meaningfully are credited in
release notes (with permission) and may be listed in a security
acknowledgments page. We don't currently offer a paid bounty.

### Our commitments to you

- We will not pursue legal action against good-faith researchers who follow
  this policy
- We will keep you informed of progress on your report
- We will credit you publicly only with your explicit permission
- We will treat your report as confidential until a fix is deployed and the
  embargo period has passed

---

*Policy version 1.0 — last updated 2026-05-17.*
*Contact: support@droneaware.io · https://droneaware.io*
