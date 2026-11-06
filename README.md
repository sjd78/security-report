# Security Report (`sec-remediate`)

Multi-branch vulnerability aggregator, dependency chain tracer, and automated remediation engine for Node.js / npm repositories.

---

## 1. Project Summary

Managing security vulnerabilities across large Node.js repositories is often fragmented between branch checkouts, local `npm audit` scans, Jira security compliance tickets, and GitHub Dependabot alerts.

`security-report` streamlines this into an automated 3-step pipeline:

1. **Step 1: Aggregate & Analyze**
   - Resolves the target repository: `org/repo` shorthand and Git URLs are cloned into an isolated `REPOS/<org>/<name>` cache; a local path is used **in place** (nothing is copied into `REPOS/`).
   - Fetches remote references and scans isolated, detached worktree snapshots of each configured branch. Scanning does not reset local branches or remove retained remediation worktrees; every report records the exact scanned commit.
   - Resolves dependency hierarchies and monorepo workspace relationships via `@npmcli/arborist` virtual trees, eliminating false cross-product ancestry when a package exists across multiple distinct versions.
   - Runs `npm audit` with **intermediate package filtering**: dependency carriers lacking direct advisories in `via` are ignored as top-level findings and preserved in ancestor chains.
   - Cross-references findings with Jira CVE tickets and GitHub Dependabot alerts, querying GitHub Advisory API and OSV to resolve CVE identifiers and **all active major version line fixes** (e.g. `2.4.5`, `3.1.6`, `4.1.3`).
   - Compares installed versions against target fixes to track **`Status` (`✅ Resolved` vs `⚠️ Open`)**, identifying flaws that remain logged in Jira or Dependabot but are already solved in code.
   - Consolidates multiple CVEs and advisories per package to calculate the optimal safe version that resolves all flaws (prioritizing safe in-major updates when installed version is known).
   - Outputs machine-readable JSON (`reports/security-report.json`) and human-readable Markdown (`reports/security-report.md`) featuring:
     - **Package Overview Table**: `Package`, `Status` (`✅ Resolved` / `⚠️ Open`), `Severity`, `Type`, `Current Version`, `Target Fix` (minimum all-findings-safe version per relevant installed major), `CVEs`, and linked `Sources`.
     - **Detailed Package Findings**: Unnumbered findings with status badges, semver-sorted installed versions, individual advisory links, and partitioned **Direct Dependencies** and **Transitive Dependency Paths**. Transitive paths retain every physical copy and root/workspace origin, including scoped parents and distinct versions of the same parent.
   - Writes `reports/security-remediation-plan.json`: a standalone schema-2 plan grouped by branch and package, with a separate approved resolution for every vulnerable installed version line, physical installation locations and complete origins, advisory evidence, coverage-linked actions, and explicit unresolved dispositions.
   - Parent-fix suggestions from npm audit are candidates, not instructions to downgrade: a parent update must move forward from the installed version in every affected declaring workspace. Stale, equal, lower, or unprovable candidates are rejected rather than displayed as upgrades.
2. **Step 2: Execute a Reviewed Plan**
   - `fix --plan <path>` consumes the saved actions without rescanning or silently choosing a different remediation.
   - Checks every selected branch's scanned SHA and manifest preconditions before applying changes. Stale plans, conflicting actions, escaping paths, and disabled override requirements fail explicitly.
   - Applies root/workspace dependency edits, persistent overrides, and lockfile re-resolution in separate `security-remediation/*` branches. It never resets the target branches or overwrites retained worktrees.
   - Runs npm lockfile operations with lifecycle scripts disabled, verifies all planned package instances against their findings, and requires a successful post-change audit.
   - Apply-only and failed runs retain the worktree for inspection. `--commit` commits verified changes on the remediation branch; `--commit --push` pushes that branch.
3. **Step 3: Publish Pull Requests**
   - `pr --plan <path>` commits, pushes, and opens one PR per target branch. Rerunning the same plan re-verifies its existing remediation branch and updates the matching open PR instead of duplicating it.
   - PR descriptions include per-installed-version targets and origin chains, saved actions, actual post-remediation versions, CVE/GHSA/npm audit/Jira/Dependabot references, verification results, and findings that remain manual or have no fix.
   - Titles are configurable through `prTitleTemplate`, `SEC_PR_TITLE_TEMPLATE`, or `--pr-title-template`.

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

# 2. Review reports/security-remediation-plan.json, then preview its actions
sec-remediate fix --plan reports/security-remediation-plan.json --dry-run

# 3. Apply and commit on separate remediation branches, without publishing PRs
sec-remediate fix --plan reports/security-remediation-plan.json --commit

# 4. Apply, verify, and publish one PR per target branch
sec-remediate pr --plan reports/security-remediation-plan.json
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
| `SEC_FORK_REPO` | `--fork-repo <owner/repo>` | Existing fork to receive remediation heads; config field `forkRepo`; PRs still target upstream | unset (publish to origin) |
| `JIRA_BASE_URL` | `--jira-base-url <url>` | Atlassian Jira instance URL (e.g., `https://my-org.atlassian.net`) | `""` |
| `JIRA_EMAIL` | `--jira-email <email>` | Jira user email address (for Basic Auth) | `""` |
| `JIRA_API_TOKEN` | `--jira-api-token <token>`| Jira API token or Personal Access Token (PAT) | `""` |
| `JIRA_PROJECT` | `--jira-project <key>` | Jira Project Key for CVE tickets | `MTA` |
| `JIRA_JQL` | `--jira-jql <query>` | Custom JQL query for Jira ticket retrieval | _Auto-generated_ |
| `SEC_COLLECTORS` | `--collectors <list>` | Active collectors to run (`npm-audit`, `jira`, `dependabot`) | `npm-audit,jira,dependabot` |
| `SEC_DEBUG` | `--debug` | Save `debug-collection-{kind}.json` and `debug-blended.json` | `false` |
| `SEC_PR_TITLE_TEMPLATE` | `--pr-title-template <text>` | PR/commit title; config field `prTitleTemplate`; supports `{targetBranch}`, `{targetPackages}`, `{summary}` | `fix(deps): {summary} ({targetBranch})` |

> **Note on Credentials:** `.security-report.json` holds API tokens and is listed in `.gitignore` — keep it untracked. The GitHub token is never written into a clone URL or `.git/config`: it is passed per git invocation via `GIT_CONFIG_*` and stripped from any git error message. Library callers can bypass config-file discovery entirely with `loadConfig({ noConfigFile: true })`; the test suite relies on this to stay hermetic.

> **Note on Configuration Validation:** If the Jira collector is enabled but its configuration is incomplete (missing `JIRA_BASE_URL` or `JIRA_API_TOKEN`), the tool automatically disables the Jira collector, logs a warning notice, and continues scanning with the remaining active collectors without failing.

If Jira authentication/access fails (HTTP 401/403), search fails, or a network error prevents collection, the collector explicitly warns that results will not include any Jira data. Authentication failures are not retried against the fallback search endpoint; other search failures report the final HTTP status. Scanning continues with the remaining sources. A successful search returning no matching tickets is not reported as an access failure.

### Example Configuration File (`.security-report.json`)

```json
{
  "repo": "konveyor/tackle2-ui",
  "forkRepo": "sjd78/tackle2-ui",
  "branches": ["main", "release-0.10", "release-0.9"],
  "branchMap": {
    "main": ["8.3.x", "8.3", "mta-8.3", "MTA 8.3"],
    "release-0.11": ["8.3.x", "8.3", "mta-8.3", "MTA 8.3"],
    "release-0.10": ["8.2.x", "8.2", "mta-8.2", "MTA 8.2"],
    "release-0.9": ["8.1.x", "8.1", "mta-8.1", "MTA 8.1"]
  },

  "githubToken": "<token, or use `gh auth token`>",
  "prTitleTemplate": "fix(deps): {targetPackages} on {targetBranch} — {summary}",
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
  "allowBreaking": false,
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
- `--no-overrides`: Leave override-only package plans for manual review.
- `--debug`: Write `debug-collection-jira.json`, `debug-collection-dependabot.json`, `debug-collection-npm-audit.json`, and `debug-blended.json` under the reports directory.

#### Collector output

Each collection records `repository` and `branches`, with findings nested at `branches[].packages[].findings`. Package names are stored on their group, not repeated on every finding.

- **Jira:** tickets are grouped by the affected package and mapped upstream branch. Package identity prefers structured GitHub advisory data, with OSV fallback for GHSA/CVE identifiers (including CVE.org links). A unique npm package overrides text extraction; a multi-package advisory uses the text hint only when that package is present in structured data. If lookup is unavailable, text extraction remains the fallback. Tracker titles support `CVE-… product: package description` without a second colon. Tickets without matching branch/version evidence stay in package-grouped `unassigned` entries instead of appearing on every branch.
- **Dependabot:** alerts belong only to the repository's actual default branch, discovered through GitHub repository metadata (falling back to `main` with a note if unavailable). Requesting a release branch first never makes it the default. The collection retains the default-branch group even when only releases were requested; the report uses only branches actually scanned.
- **npm audit / Arborist:** each branch's audit supplies package advisories; package instances retain installed versions, physical locations, and declaring root/workspace origins. Collection files omit worktree trees, lockfile snapshots, and remediation actions.

CVEs are stored on the issue/advisory findings, without parallel `allTickets`/`allAlerts` copies or a second package-level CVE list. Jira and Dependabot retain their native `cve` field; npm advisories use a deduplicated `cves` array. A package that cannot be identified remains under `packageName: null`.

The blender collates all enabled collector sources per branch and package, owns canonical `findings`, and calculates `affectedVersions` as deduplicated `{ vulnerableRange, firstPatchedVersion }` pairs without collapsing different release lines to one patch target. The report, registry safety assessment, and remediation planner consume that evidence directly. With `--debug`, `debug-blended.json` exposes the same handoff as `{ repository, branches: [{ branch, baseCommit?, error?, packages: [{ packageName, findings, affectedVersions }] }] }`. It excludes snapshots, Arborist trees, and legacy evidence copies; failed branches retain their error with an empty package list. Without debug, none of the four debug files are written.

Range/patch pairs remain associated with their findings. A known patch supersedes a redundant null-patch entry only for the same finding and normalized range; other missing patch values stay `null`, and invalid or contradictory evidence is retained for planner review. GitHub's global advisory API supplies `vulnerabilities[].first_patched_version` as a string, unlike Dependabot's `security_vulnerability.first_patched_version.identifier` object. OSV supplies paired `introduced`/`fixed` events. Package matching keeps `joi` and `@hapi/joi`, for example, distinct. Markdown advisory details display the blended ranges and patch floors, while the target-fix list uses those same paired values.

For blended data, Markdown **Target Fix** selects the lowest known stable patch boundary that satisfies every finding, with one entry per currently used major rather than every historical patch. If a vulnerable installed major has no safe candidate, show the smallest necessary higher-major fix instead. Unused release lines are omitted; individual advisory details retain their full evidence. This is a display minimum, not a resolution instruction: the planner still selects the newest published safe patch within each installed major/minor line and may require manual review for cross-line upgrades.

#### Remediation-plan artifact

Every scan writes `security-remediation-plan.json` alongside the existing JSON and Markdown reports. Generating the plan does not edit target manifests or lockfiles.

* Top level: `schemaVersion: "2.0.0"`, `kind: "security-remediation-plan"`, `generatedAt`, repository identity/path, summary counts, and `branches`.
* Each branch records its `baseCommit`, a summary sentence, `packages`, reconciled `actions`, and any `blockers`. Its status is `ready`, `blocked`, or `no-op`; `no-op` means no executable actions, not necessarily no findings.
* Each package keeps installed versions, normalized advisory evidence (`constraints` and source `references`), and a disposition: `ready`, `resolved`, `manual-review`, `no-fix`, or `not-installed`.
* Every vulnerable installed version has a resolution with its approved target or explicit unresolved status, applicable finding IDs, physical package instances, and complete root/workspace origin chains.
* Package `risk: { fixType, breaking, reasons }` is derived from canonical actions and remains separate from per-resolution target safety. `fixType` is `safe-fix`, `override-required`, `parent-upgrade`, `breaking-upgrade`, or `unknown`; `breaking` is independently `true`, `false`, or `null` when compatibility cannot be established.
* Actions are structured data: `update-dependency` identifies a manifest, dependency section, package, `expectedRange`, and `targetRange`; `set-override` identifies the nested override scope, expected value, and target version; `update-lockfile` requests re-resolution within the declared constraints. Actions link back to the resolution IDs and motivating package/finding references they cover.
* Branch actions deduplicate shared edits while retaining complete resolution coverage. Conflicting edits, missing snapshots, and scan failures block execution rather than silently selecting a target.
* Targets must satisfy every known advisory on each affected version line. Missing evidence and unsupported ranges remain explicit manual-review items rather than speculative edits.

Review package dispositions and branch blockers before using an action plan. Planned fixes are not verified resolutions; verification happens only after applying changes.

---

### `sec-remediate fix [repo] --plan <path>` (alias: `remediate`)

Executes a saved remediation plan; it does **not** scan or regenerate the plan. The optional repository argument overrides the configured repository, otherwise the plan's recorded local path is used. The repository origin, when recorded, must match.

**Options:**
- `--plan <path>`: Required saved `security-remediation-plan.json`.
- `-b, --branches <branches>`: Select branches already present in the plan; omitted means all saved branches.
- `--packages <names>`: Select comma-separated vulnerable package names, not their carrier/parent packages; combine with a single `--branches <branch>` to target one release.
- `--fix-types <types>`: Select comma-separated `safe-fix`, `override-required`, `parent-upgrade`, or `breaking-upgrade` categories.
- `--no-breaking`: Exclude breaking and unknown-risk remediations, then verify that npm's actual selected-package resolutions stay on compatible scanned version lines before publishing.
- `--dry-run`: Validate branch snapshots, manifest preconditions, policy, and title text; print actions without applying changes, running post-change verification, committing, pushing, or creating PRs.
- `--commit`: Commit verified changes on a separate remediation branch.
- `--push`: Push the remediation branch; requires `--commit`.
- `--fork-repo <owner/repo>`: Push remediation branches to an existing fork instead of origin; the scanned origin remains the PR base repository.
- `--no-overrides`: Reject a plan requiring overrides rather than silently skipping its actions.
- `--pr-title-template <text>`, `--github-token <token>`, `--repos-dir <path>`, `--reports-dir <path>`.

Without `--commit`, the verified worktree is retained and its path printed. Failed execution also retains its worktree. A rerun refuses to overwrite it: review the files, then remove that worktree explicitly when it is no longer needed.

#### Transitive resolution: limitations and selected direction

`update-lockfile` records an intended re-resolution, not a guarantee that npm will change every transitive copy. The user observed `npm update joi --package-lock-only` leaving the lockfile unchanged. Direct Arborist named updates use that same mechanism and are not a demonstrated workaround on this repository.

Arborist's `audit({ fix: true })` takes a different, vulnerability-aware path. A scratch-registry experiment updated a purely transitive dependency without changing `package.json`, adding overrides, or writing `node_modules`. Separate experiments audited first, filtered the report to one package, then built/reified the ideal tree; only the selected direct or transitive package changed. Report filtering is implementation-dependent, not a public package whitelist or a guarantee against collateral graph changes. Audit fix also does not automatically consume Jira-only findings. These experiments are not proof against the user's actual dependency graph.

**Chosen direction: transient pins for in-range updates.** This is the agreed execution policy, not an implementation claim; the current executor still attempts npm named updates:

1. Apply reviewed manifest edits.
2. Add generated, version/ancestor-scoped temporary overrides for approved targets, keeping distinct installed version lines independently scoped.
3. Resolve the lockfile with lifecycle scripts disabled.
4. Remove only the generated temporary overrides. Preserve pre-existing overrides and reviewed persistent edits; restore the intended final manifest on failure too. Temporary pins must not be committed.
5. Verify every approved resolution and the change scope against the final manifest **without temporary pins**, then run the post-change audit.

If a target violates the final parent constraints, removing its pin leaves an invalid graph: require a reviewed parent upgrade, persistent override, or manual review instead. Do not add root transitive declarations or silently broaden the selected fix. Do not run another unconstrained install after pin removal, because it can undo the chosen resolutions.

A successful command exit is not success if an approved target is missing, a vulnerable copy remains, or unrelated packages changed outside the reviewed scope. Verification failure retains the worktree and prevents publication. Reusing an already-fixed branch must reprove its approved outcomes rather than manufacture another diff.


### `sec-remediate pr [repo] --plan <path>`

Executes the same saved plan, commits and pushes verified remediation branches, then creates or updates an open GitHub PR for each base/head pair. Accepts the `fix` options above except `--commit` and `--push`, which are implicit. Requires an origin URL identifying the upstream GitHub owner/repository, push access to the selected publication destination, and a GitHub token able to open pull requests against upstream. SSH origins still use SSH authentication; HTTPS Git operations receive the configured token per invocation. `GITHUB_API_URL` supports GitHub Enterprise.

Existing remediation branches are reused only when their commit identifies the same saved plan and their changed files remain within that plan. They are re-audited before publication. Target branch changes require a fresh scan and review; the executor never rebases or force-pushes stale plans.

Execution writes `security-remediation-results.json` under the configured reports directory, including dry-run/unverified state, observed verification results, commit/PR details, or error and retained-worktree information. Unreadable or unsupported plan files are rejected before execution. Audit failure or a still-vulnerable planned package prevents publication. Manual/no-fix findings are disclosed rather than counted as fixed. `npm-shrinkwrap.json` repositories require manual review because the plan targets `package-lock.json`.

#### Publishing from a fork

Keep `repo` pointed at the upstream repository and set `forkRepo` to the existing fork receiving your changes. For example, the configuration above scans `konveyor/tackle2-ui`, pushes only the remediation head to `sjd78/tackle2-ui`, and opens the PR against the original upstream target branch.

Precedence: `--fork-repo` > `SEC_FORK_REPO` > config-file `forkRepo`. Omit the setting to retain same-repository publication. Empty, invalid, or upstream-identical fork identities are rejected rather than silently switching the push destination.

```bash
sec-remediate pr --plan reports/security-remediation-plan.json \
  --fork-repo sjd78/tackle2-ui \
  --branches release-0.11 --no-breaking
```

`fix --commit --push` honors the same destination. `fix --commit` still creates only a local commit. The upstream repository remains `origin` for scanning, stale-plan checks, and the PR base; fork configuration never changes existing Git remotes.

Fork URLs retain the upstream origin's HTTPS/SSH transport and host, including GitHub Enterprise hosts. The fork must already exist on that host and belong to the upstream repository's fork network for GitHub to accept the PR. The tool does not create a fork, reset/synchronize its default branch, or push remediation heads to upstream. A fork behind upstream is fine: the new remediation branch starts at the scanned upstream commit.

PR lookup and creation use the fork owner's qualified head (`sjd78:<remediation-branch>`), with an explicit head repository for cross-repository requests. Replays read the fork's head in an isolated local tracking namespace, even if upstream has a different branch of the same name. Results and dry-run output identify both the base and head repositories.

Access failures, rejected pushes, and conflicting fork heads fail explicitly; there is **no fallback push to origin** and no force push. A failed applied/committed run keeps its worktree for inspection. Dry runs skip fork-specific lookups, fetches, pushes, and configuration changes; normal repository preparation can still fetch remotes already configured by the user.

#### Selecting fixes

The selectors apply to both `fix` and `pr`. Multiple fix types are ORed; branch, package, type, and no-breaking restrictions intersect. Unknown branch/package/type names and empty lists fail before applying changes.

```bash
# Only safe fixes
sec-remediate fix --plan reports/security-remediation-plan.json --fix-types safe-fix --dry-run

# Only required overrides that do not cross incompatible version lines
sec-remediate pr --plan reports/security-remediation-plan.json --fix-types override-required --no-breaking

# One branch and an explicit package list; allow either category, but not breaking upgrades
sec-remediate pr --plan reports/security-remediation-plan.json \
  --branches release-0.11 --packages axios,js-yaml \
  --fix-types safe-fix,override-required --no-breaking
```

`safe-fix` means a known semver-compatible fix with neither a persistent override nor a direct-parent upgrade. Override classification takes precedence: an override that crosses a major is still `override-required`, but its independent `breaking: true` flag makes `--no-breaking` exclude it. Parent upgrades have their own category even when nonbreaking.

Compatibility follows npm's caret version lines: major for stable releases, minor for `0.x`, and patch for `0.0.x`. Downgrades, incompatible prerelease transitions, widened incompatible ranges, and missing evidence are not treated as safe. This is a semver policy, not proof of application/API compatibility.

Without filters, all ready package actions remain eligible. Set `"allowBreaking": false` in the config file to enable the no-breaking policy by default (`allowBreaking` otherwise defaults to `true`); `--no-breaking` also enforces it explicitly.

Execution never rewrites the reviewed plan. It selects whole package fixes, keeps required shared actions intact, and records excluded ready packages as `skipped` with reasons in results and PR descriptions. Shared parent edits and npm lockfile resolution may incidentally affect other dependencies, but excluded packages are not counted as fixed. Changing the effective selection produces a separate remediation head/PR; repeating the same selection reuses its existing head.

If nothing matches, the result is an explicit unverified `no-op`, not a clean audit or a successful fix. No npm changes or PR publishing occurs.

#### PR title templates

Precedence: CLI `--pr-title-template` > `SEC_PR_TITLE_TEMPLATE` > config-file `prTitleTemplate` > built-in default. Available tokens:

- `{targetBranch}`: the PR's base branch.
- `{targetPackages}`: comma-separated names of the packages being remediated.
- `{summary}`: the branch plan's summary sentence.

Unknown placeholders, empty titles, and multiline titles are rejected before applying changes.

```bash
export SEC_PR_TITLE_TEMPLATE='fix(deps): {targetPackages} [{targetBranch}] — {summary}'
sec-remediate pr --plan reports/security-remediation-plan.json
```

---

## 5. Sample Report Format

### Package Vulnerability Overview Table

| Package | Status | Severity | Type | Current Version | Target Fix | CVEs | Sources |
| :--- | :---: | :---: | :---: | :--- | :--- | :--- | :--- |
| **`fast-uri`** | ⚠️ Open | **HIGH** | Direct | `2.4.2` | `2.4.5` | `CVE-2026-75931` | [npm audit](https://github.com/advisories/GHSA-5jgf-p345-68v8) |
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
> _Note: Package is both direct and transitive. Manifest edits address the direct declarations; transitive instances require separate resolution and verification._

1. Update `package.json` file(s):
   - Bump `js-yaml` from `^4.3.0` to `^4.3.2` in `dependencies` (`client/package.json`)
   - Bump `js-yaml` from `^4.3.0` to `^4.3.2` in `devDependencies` (`cypress/package.json`)
2. Required lockfile resolution (not a standalone command):
   - Re-resolve `js-yaml` to the approved per-instance targets after the manifest edits.
   - In-range transitive copies use the chosen scoped temporary-pin policy, with generated pins removed before final verification. This execution policy is not yet implemented; a standalone `npm update` command is not presented as a sufficient fix.
3. Verify every approved direct/transitive resolution against the resulting graph; stop if any target is not realized. Do not infer success from the command's exit code.
```

---

## 6. Commit and PR Contents

Verified commits and PRs use the configured title and a generated Markdown body describing:

- The target branch and scanned base commit.
- Canonical manifest/override/lockfile actions from the reviewed plan.
- The actual verified installed versions for each remediated package.
- Each motivating advisory and its npm audit, GHSA, CVE, Jira, and Dependabot references.
- Post-change audit results and unresolved findings, without claiming that unplanned issues were fixed.

Commits include a `Security-Remediation-Plan` digest trailer used to recognize safe reruns. Execution results, not the plan's expected outcomes, establish which packages were resolved.

---

## 7. Running Tests

```bash
npm test
```

Runs the unit and integration suite on Node's native `node:test` runner. `git` and `npm` must be on `PATH`. Integration tests run real npm against an isolated loopback registry and real Git against temporary local bare remotes; PR protocol tests use a loopback GitHub REST fixture.

Tests skip developer config discovery with `noConfigFile: true`, except dedicated configuration-discovery tests that run in a temporary working directory with known fixture files. Registry fixtures isolate npm configuration and caches so developer credentials are not used.
