# Security Report (`sec-remediate`)

Multi-branch vulnerability aggregator, dependency chain tracer, and automated remediation engine for Node.js / npm repositories.

---

## 1. Project Summary

Managing security vulnerabilities across large Node.js repositories is often fragmented between branch checkouts, local `npm audit` scans, Jira security compliance tickets, and GitHub Dependabot alerts.

`security-report` streamlines this into an automated 3-step pipeline:

1. **Step 1: Aggregate & Analyze**
   - Clones target repositories (GitHub `org/repo` format, URLs, or local folders) into an isolated `REPOS/` directory.
   - Spins up detached `git worktree` instances per target branch to prevent workspace contamination.
   - Runs `npm audit` and parses the full `npm ls` ancestor hierarchy to trace direct vs. indirect (transitive) dependency chains.
   - Cross-references and enriches findings with Jira CVE tickets and GitHub Dependabot alerts.
   - Outputs machine-readable JSON (`reports/security-report.json`) and human-readable Markdown (`reports/security-report.md`).

2. **Step 2: Automated Remediation**
   - Modeled after `npm-check-updates`: updates `package.json` semver constraints for direct roots (preserving formatting and `^`/`~` prefixes).
   - Applies npm `overrides` for transitive vulnerabilities when upstream parent packages lack a patch.
   - Performs atomic lockfile synchronizations (`npm install --package-lock-only`).
   - Runs a post-remediation audit scan to verify that vulnerabilities are resolved.

3. **Step 3: Structured Commit Generation & Publishing**
   - Generates conventional commit messages linking CVE IDs, GHSA identifiers, advisory URLs, Jira tickets, Dependabot alert numbers, and the exact dependency path.
   - Stages and commits changes directly on the target branch worktrees with optional remote push.

---

## 2. Quick Start

### Prerequisites
- Node.js `>= 20.0.0`
- Git `>= 2.20.0`
- npm `>= 7.0.0`

### Installation

```bash
# Clone and install dependencies
git clone <this-repo-url> security-report
cd security-report
npm install

# Link binary globally or use directly via node
npm link
# or run with: ./bin/sec-remediate.js
```

### Basic Usage

```bash
# 1. Scan multiple branches on a repository (Step 1)
sec-remediate scan facebook/react --branches main,release/18.x

# 2. Preview remediations and commit messages without modifying files (Dry-Run)
sec-remediate fix facebook/react --branches main --dry-run

# 3. Remediate and commit changes to the target branches (Step 2 + Step 3)
sec-remediate fix facebook/react --branches main,release/18.x --commit

# 4. Remediate, commit, and push to remote
sec-remediate fix facebook/react --branches main --commit --push
```

---

## 3. Configuration Variables

Configuration can be provided via environment variables, CLI options, or a `.security-report.json` file in the working directory.

| Variable | CLI Flag | Description | Default |
| :--- | :--- | :--- | :--- |
| `SEC_REPO` | `repo` / `[repo]` | Target repository specifier (`org/repo`, URL, or local path) | `null` |
| `SEC_REPOS_DIR` | `--repos-dir <path>` | Directory where repositories are cloned and cached | `./REPOS` |
| `SEC_REPORTS_DIR` | `--reports-dir <path>` | Directory where JSON and Markdown reports are saved | `./reports` |
| `SEC_BRANCH_MAP` | `--branch-map <mapping>` | Translation table mapping upstream branches to downstream versions (e.g. `main=8.3,release-0.11=8.2,release-0.10=8.1`) | Built-in MTA map |
| `GIT_PROTOCOL` | — | Git clone protocol (`https` or `ssh`) | `https` |
| `GITHUB_TOKEN` | `--github-token <token>` | GitHub Personal Access Token for Dependabot alerts and private repos | `""` |
| `GITHUB_API_URL` | — | Base URL for GitHub API (for GitHub Enterprise) | `https://api.github.com` |
| `JIRA_BASE_URL` | `--jira-base-url <url>` | Atlassian Jira instance URL (e.g., `https://my-org.atlassian.net`) | `""` |
| `JIRA_EMAIL` | `--jira-email <email>` | Jira user email address (for Basic Auth) | `""` |
| `JIRA_API_TOKEN` | `--jira-api-token <token>`| Jira API token or Personal Access Token (PAT) | `""` |
| `JIRA_PROJECT` | `--jira-project <key>` | Jira Project Key for CVE tickets | `MTA` |
| `JIRA_JQL` | `--jira-jql <query>` | Custom JQL query for Jira ticket retrieval | _Auto-generated_ |
| `SEC_DEBUG` | `--debug` | Save raw collector outputs to `security-<name>-collection.json` | `false` |

### Example Configuration File (`.security-report.json`)

```json
{
  "repo": "konveyor/tackle2-ui",
  "branches": ["main", "release-0.12", "release-0.11", "release-0.10"],
  "reposDir": "REPOS",
  "reportsDir": "reports",
  "gitProtocol": "https",
  "branchMap": {
    "main": ["8.3.x", "8.3", "mta-8.3", "MTA 8.3"],
    "release-0.12": ["8.3.x", "8.3", "mta-8.3", "MTA 8.3"],
    "release-0.11": ["8.2.x", "8.2", "mta-8.2", "MTA 8.2"],
    "release-0.10": ["8.1.x", "8.1", "mta-8.1", "MTA 8.1"]
  },
  "jira": {
    "baseUrl": "https://redhat.atlassian.net",
    "project": "MTA",
    "jql": "project = \"Migration Toolkit for Applications\" and labels = \"security\" and (summary ~ \"mta-ui-rhel8\" or summary ~ \"mta-ui-rhel9\" or summary ~ \"mta-ui-rhel10\") and status != Closed"
  },
  "allowOverrides": true,
  "debug": false
}
```

---

## 4. CLI Commands Reference

### `sec-remediate scan [repo]` (or `sec-remediate report [repo]`)

Scans target repository across branches, blends vulnerability sources, and produces intermediate reports. If `[repo]` is omitted, the `repo` value from `.security-report.json` is used.

```bash
sec-remediate scan [repo] [options]
```

**Options:**
- `-b, --branches <branches>`: Comma-separated list of branches to scan (e.g. `main,release/1.0`).
- `--all-branches`: Scan all branches found in the repository.
- `--repos-dir <path>`: Custom directory to store cloned repositories (default: `REPOS`).
- `--reports-dir <path>`: Custom directory for generated reports (default: `reports`).
- `--github-token <token>`: GitHub API token.
- `--jira-base-url <url>`: Atlassian Jira base URL.
- `--jira-email <email>`: Jira user email.
- `--jira-api-token <token>`: Jira API token.
- `--jira-project <project>`: Jira Project Key (default: `MTA`).
- `--debug`: Save intermediate collector outputs to `security-<name>-collection.json`.
---

### `sec-remediate fix [repo]` (or `sec-remediate remediate [repo]`)

Applies remediations (`package.json` updates + lockfile updates), verifies resolution, and optionally creates Git commits. If `[repo]` is omitted, the `repo` value from `.security-report.json` is used.

```bash
sec-remediate fix [repo] [options]
```

**Options:**
- `-b, --branches <branches>`: Comma-separated list of branches to remediate.
- `--all-branches`: Remediate all branches found in the repository.
- `--dry-run`: Preview changes and generated commit messages without writing to disk.
- `--commit`: Create Git commits on the target branches with motivating links.
- `--push`: Push created commits to the remote repository.
- `--no-overrides`: Do not insert npm `overrides` into `package.json`.
- All connection options (`--github-token`, `--jira-*`, `--repos-dir`, `--reports-dir`).

---

## 5. Sample Commit Message

When running with `--commit`, the engine creates structured commit messages:

```text
fix(deps): remediate 2 vulnerabilities on branch main

Automated security remediation applied based on aggregated audit findings.

### Resolved Vulnerabilities:
- [HIGH] tough-cookie (2.5.0 -> 4.1.3) (CVE-2023-26136)
  - Title: Prototype Pollution in tough-cookie
  - Advisory: https://github.com/advisories/GHSA-72xf-g2v4-qvf3
  - Jira: SEC-1042 (https://company.atlassian.net/browse/SEC-1042)
  - Dependabot: #42 (https://github.com/org/repo/security/dependabot/42)
  - Chain: request-lib@1.2.0 -> sub-dep@0.4.1 -> tough-cookie@2.5.0
- [CRITICAL] lodash (4.17.15 -> 4.17.21) (CVE-2021-23337)
  - Title: Command Injection in lodash
  - Advisory: https://github.com/advisories/GHSA-35jh-r3h4-6jhm
  - Chain: lodash@4.17.15

### Changes Applied:
- Updated lodash ^4.17.15 -> ^4.17.21 in dependencies
- Added override: "tough-cookie": "4.1.3"
- Synchronized package-lock.json

Verification: Post-remediation npm audit scan reported 0 remaining vulnerabilities.
```

---

## 6. Running Tests

```bash
npm test
```

Runs the complete unit and integration test suite using Node.js native `node:test` runner.
