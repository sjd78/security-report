# Security Report (`sec-remediate`)

Multi-branch vulnerability aggregator, dependency chain tracer, and automated remediation engine for Node.js / npm repositories.

---

## 1. Project Summary

Managing security vulnerabilities across large Node.js repositories is often fragmented between branch checkouts, local `npm audit` scans, Jira security compliance tickets, and GitHub Dependabot alerts.

`security-report` streamlines this into an automated 3-step pipeline:

1. **Step 1: Aggregate & Analyze**
   - Resolves the target repository: `org/repo` shorthand and Git URLs are cloned into an isolated `REPOS/<org>/<name>` cache; a local path is used **in place** (nothing is copied into `REPOS/`).
   - Detaches the base repository's `HEAD` — including local targets — so every branch name is free, then creates one `git worktree` per target branch, reset to the latest fetched `origin/<branch>` when that remote branch exists (otherwise the existing local branch is used, or a new one is created).
   - Runs `npm audit` with **intermediate package filtering**: dependency carriers lacking direct advisories in `via` are ignored as top-level findings and preserved in ancestor chains.
   - Cross-references findings with Jira CVE tickets and GitHub Dependabot alerts, querying GitHub Advisory API and OSV to resolve CVE identifiers and **all active major version line fixes** (e.g. `2.4.5`, `3.1.6`, `4.1.3`).
   - Compares installed versions against target fixes to track **`Status` (`✅ Resolved` vs `⚠️ Open`)**, identifying flaws that remain logged in Jira or Dependabot but are already solved in code.
   - Consolidates multiple CVEs and advisories per package to calculate the optimal safe version that resolves all flaws (prioritizing safe in-major updates when installed version is known).
   - Outputs machine-readable JSON (`reports/security-report.json`) and human-readable Markdown (`reports/security-report.md`) featuring:
     - **Package Overview Table**: `Package`, `Status` (`✅ Resolved` / `⚠️ Open`), `Severity`, `Type`, `Current Version`, `Target Fix` (all major line fixes separated by `<br>`), `CVEs` (separated by `<br>`), and `Sources` (linked advisories, Jira tickets, Dependabot alerts separated by `<br>`).
     - **Detailed Package Findings**: Unnumbered findings with status badges, explicit current and target fix versions, individual advisory links, and strictly partitioned **Direct Dependencies** and **Transitive Dependency Paths** in compact code blocks (`<pkgFile>/<section>/...`).
2. **Step 2: Automated Remediation (5-Tier Preference Hierarchy)**
   - **`bump-direct-and-lockfile`**: For dual dependencies (`Direct & Indirect`, e.g. `js-yaml`), bumps the direct `package.json` semver constraint AND issues lockfile updates to synchronize all transitive instances.
   - **`bump-direct`**: Directly updates `package.json` semver constraints for direct dependencies (preserving formatting and `^`/`~` prefixes).
   - **`bump-direct-parent`**: If a direct root parent (e.g. `msw`) has an update available that patches the transitive dependency, bumps the direct parent in `package.json`.
   - **`lockfile-update`**: If the parent package's declared semver range already permits the safe patched version (e.g. parent requires `>=0.7.0 <0.9.0` and `0.8.8` is safe), updates the lockfile directly without introducing unnecessary `package.json` overrides.
   - **`package-override`**: Fallback applied only when parent ranges strictly forbid the safe version and no direct parent update exists.
   - Packages already resolved in the repository skip redundant edits and lockfile changes.
   - Performs atomic lockfile synchronization (`npm install --package-lock-only`, then `npm update <pkg> --package-lock-only` for each package that must move within existing ranges) and post-remediation audit verification.
   - Without `--commit`, the branch worktree is **kept** and its path printed — it holds the only copy of the applied fix. A failed remediation also keeps its worktree for inspection.
3. **Step 3: Structured Commit Generation & Publishing**
   - Generates conventional commit messages linking CVE IDs, GHSA identifiers, advisory URLs, Jira tickets, Dependabot alert numbers, and the exact dependency path.
   - Stages the touched `package.json` files (root and workspaces) plus `package-lock.json`, commits on the target branch, and optionally pushes. The commit is guaranteed to advance `refs/heads/<branch>`; if the branch is held by another worktree the run aborts instead of stranding the commit.

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

Configuration is read from CLI options, environment variables, and a `.security-report.json` (or `security-report.config.json`) file in the working directory.

Precedence is **CLI option > environment variable > config file**, except for `githubToken`, `jira.baseUrl`, `jira.email` and `jira.apiToken`, where an explicit config-file value takes precedence over the environment variable.

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
| `SEC_COLLECTORS` | `--collectors <list>` | Active collectors to run (`npm-audit`, `jira`, `dependabot`) | `npm-audit,jira,dependabot` |
| `SEC_DEBUG` | `--debug` | Save raw collector outputs to `security-<name>-collection.json` | `false` |

> **Note on Credentials:** `.security-report.json` holds API tokens and is listed in `.gitignore` — keep it untracked. The GitHub token is never written into a clone URL or `.git/config`: it is passed per git invocation via `GIT_CONFIG_*` and stripped from any git error message. Library callers can bypass config-file discovery entirely with `loadConfig({ noConfigFile: true })`; the test suite relies on this to stay hermetic.

> **Note on Configuration Validation:** If the Jira collector is enabled but its configuration is incomplete (missing `JIRA_BASE_URL` or `JIRA_API_TOKEN`), the tool automatically disables the Jira collector, logs a warning notice, and continues scanning with the remaining active collectors without failing.

### Example Configuration File (`.security-report.json`)

```json
{
  "repo": "konveyor/tackle2-ui",
  "branches": ["main", "release-0.10", "release-0.9"],
  "branchMap": {
    "main": ["8.3.x", "8.3", "mta-8.3", "MTA 8.3"],
    "release-0.11": ["8.3.x", "8.3", "mta-8.3", "MTA 8.3"],
    "release-0.10": ["8.2.x", "8.2", "mta-8.2", "MTA 8.2"],
    "release-0.9": ["8.1.x", "8.1", "mta-8.1", "MTA 8.1"]
  },

  "githubToken": "<token, or use `gh auth token`>",
  "jira": {
    "baseUrl": "https://redhat.atlassian.net",
    "project": "MTA",
    "email": "<name>@redhat.com",
    "apiToken": "<token>",
    "jql": "project = \"Migration Toolkit for Applications\" and labels = \"security\" and (summary ~ \"mta-ui-rhel8\" or summary ~ \"mta-ui-rhel9\" or summary ~ \"mta-ui-rhel10\") and status != Closed"
  },

  "reposDir": "REPOS",
  "reportsDir": "reports",
  "collectors": ["npm-audit", "jira", "dependabot"],
  "allowOverrides": true,
  "debug": false
}
```

---

## 4. CLI Commands Reference

### `sec-remediate scan [repo]` (alias: `sec-remediate report [repo]`)

Scans the target repository across branches, blends vulnerability sources, and produces the intermediate reports. If `[repo]` is omitted, the `repo` value from the config file (or `SEC_REPO`) is used. `report` is a true alias and accepts every option below.

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
- `--jira-jql <query>`: Custom JQL query for Jira ticket retrieval.
- `--branch-map <mapping>`: Upstream branch to downstream version mapping (e.g. `main=8.3,release-0.11=8.2`).
- `--collectors <list>`: Comma-separated list of collectors to enable (e.g. `jira` or `npm-audit,jira`).
- `--no-npm-audit`: Disable npm audit collector.
- `--no-jira`: Disable Jira collector.
- `--no-dependabot`: Disable GitHub Dependabot collector.
- `--debug`: Save intermediate collector outputs to `security-<name>-collection.json`.

---

### `sec-remediate fix [repo]` (or `sec-remediate remediate [repo]`)

Runs a scan, then applies remediations (`package.json` updates, lockfile synchronization), verifies the result with a second `npm audit`, and optionally creates Git commits. If `[repo]` is omitted, the `repo` value from the config file (or `SEC_REPO`) is used.

```bash
sec-remediate fix [repo] [options]
```

**Options:**
- `-b, --branches <branches>`: Comma-separated list of branches to remediate.
- `--all-branches`: Remediate all branches found in the repository.
- `--dry-run`: Print the changes and the generated commit message without touching `package.json` or the lockfile. The scan reports in `--reports-dir` are still written.
- `--commit`: Create Git commits on the target branches with motivating links.
- `--push`: Push created commits to the remote repository. Requires `--commit`; on its own it has no effect.
- `--no-overrides`: Do not insert npm `overrides` into `package.json`; findings that only have an override strategy are left unremediated.
- All connection and path options from `scan` (`--github-token`, `--jira-*`, `--branch-map`, `--repos-dir`, `--reports-dir`, `--collectors`, `--no-*`, `--debug`).

Without `--commit` and without `--dry-run` the changes are applied and the worktree is retained; the path is printed so the result can be reviewed and committed by hand.

---

## 5. Sample Report Format

### Package Vulnerability Overview Table

| Package | Status | Severity | Type | Current Version | Target Fix | CVEs | Sources |
| :--- | :---: | :---: | :---: | :--- | :--- | :--- | :--- |
| **`fast-uri`** | ⚠️ Open | **HIGH** | Direct | `2.4.2` | `2.4.5`<br>`3.1.6`<br>`4.1.3` | `CVE-2026-75931` | [npm audit](https://github.com/advisories/GHSA-5jgf-p345-68v8) |
| **`qs`** | ✅ Resolved | **HIGH** | Direct | `6.16.0` | `6.16.0` | `CVE-2026-82417` | [MTA-7680](https://issues.example.com/browse/MTA-7680)<br>[#42](https://github.com/org/repo/security/dependabot/42) |

### Detailed Package Finding

```markdown
#### `js-yaml` — HIGH (⚠️ Open)

- **Status:** ⚠️ Open (installed version `3.15.1, 4.3.0` is vulnerable)
- **Current Version:** `3.15.1, 4.3.0`
- **Target Fix Version:** `4.3.2`
- **CVE Identifiers (1):** `CVE-2026-82418`
- **Jira Ticket:** [MTA-7685](https://issues.example.com/browse/MTA-7685)
- **Tracked Advisories & CVEs (1):**
  - [Advisory](https://github.com/advisories/GHSA-xxxx) - [Jira MTA-7685](https://issues.example.com/browse/MTA-7685) - `CVE-2026-82418` js-yaml prototype pollution
- **Dependency Type:** Direct & Indirect
- **Direct Dependencies:**
  ```text
  client/package.json/dependencies/js-yaml@^4.3.0
  cypress/package.json/devDependencies/js-yaml@^4.3.0
  ```
- **Transitive Dependency Path:**
  ```text
  package.json/devDependencies/eslint/.../js-yaml@3.15.1
  client/package.json/dependencies/jest/.../js-yaml@3.15.1
  ```
> _Note: Compact path summary shown. To inspect full transitive tree, run `npm ls js-yaml` or `npm why js-yaml`._

**Consolidated Remediation Plan (bump-direct-and-lockfile):**
> _Note: Package is both a direct dependency and required transitively. Resolution updates package.json semver and synchronizes lockfile for all instances._

1. Update `package.json` file(s):
   - Bump `js-yaml` from `^4.3.0` to `^4.3.2` in `dependencies` (`client/package.json`)
   - Bump `js-yaml` from `^4.3.0` to `^4.3.2` in `devDependencies` (`cypress/package.json`)
2. Synchronize lockfile:
   ```bash
   npm update js-yaml --package-lock-only
   ```
```

---

## 6. Sample Commit Message

When running with `--commit`, the engine creates structured commit messages:

```text
fix(deps): remediate 2 vulnerable packages on branch main

Automated security remediation applied based on aggregated audit findings.

### Resolved Packages & Security Advisories:
- [HIGH] tough-cookie (2.5.0 -> 4.1.3) (CVE-2023-26136)
  - Title: Prototype Pollution in tough-cookie
  - Advisory: https://github.com/advisories/GHSA-72xf-g2v4-qvf3
  - Jira: MTA-7680 (https://issues.example.com/browse/MTA-7680)
  - Dependabot: #42 (https://github.com/org/repo/security/dependabot/42)
  - Chain: package.json/dependencies/request-lib/.../tough-cookie@2.5.0
- [CRITICAL] lodash (4.17.15 -> 4.17.21) (CVE-2021-23337)
  - Title: Command Injection in lodash
  - Advisory: https://github.com/advisories/GHSA-35jh-r3h4-6jhm
  - Chain: package.json/dependencies/lodash@4.17.15

### Changes Applied:
- Updated lodash ^4.17.15 -> ^4.17.21 in dependencies
- Added override: "tough-cookie": "4.1.3"
- Synchronized package-lock.json

Verification: Post-remediation npm audit scan reported 0 remaining vulnerabilities.
```

---

## 7. Running Tests

```bash
npm test
```

Runs the complete unit and integration suite on Node's native `node:test` runner (no external test framework). `git` and `npm` must be on `PATH`; the integration test creates throwaway repositories under the system temp directory.

The suite is hermetic: every test that touches `loadConfig` passes `noConfigFile: true`, so a `.security-report.json` in the working directory is never read and no credential ever leaves the machine during a test run.
