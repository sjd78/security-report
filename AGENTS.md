# Security Vulnerability Blender & Automated Remediation Engine (`security-report`)

## 1. Executive Summary & Design Rationale

Managing security vulnerabilities across large Node.js / npm codebases is typically fragmented:
- **npm audit** detects package-level vulnerabilities and identifies affected sub-graphs, but is branch-local and lacks business context.
- **Jira CVE tickets** track security compliance, CVE identifiers, SLAs, and security team workflows, but lack automated code-level remediation links.
- **GitHub Dependabot** flags alert numbers and repository security advisories, but automated PRs frequently create merge conflicts across multiple release branches.

This project unifies all three sources across multiple Git branches in a single repository and provides a 3-step automated workflow:
1. **Aggregate & Analyze (Step 1)**: Ingest `npm audit` across branches (isolated via Git worktrees), blend with Jira CVE tickets and GitHub Dependabot alerts, trace direct vs. indirect ancestor chains, and generate a normalized intermediate report (`JSON` and `Markdown`).
2. **Remediate (Step 2)**: Execute safe, deterministic dependency updates modeled after `npm-check-updates` (`package.json` updates first, followed by atomic lockfile synchronization and post-remediation audit verification).
3. **Commit & Trace (Step 3)**: Generate rich conventional Git commit messages linking CVEs, Jira tickets, Dependabot alerts, and exact ancestor chains, and commit directly to the target branches.

---

## 2. System Architecture & Data Flow

```mermaid
flowchart TD
    subgraph RepoManager [Git & Worktree Manager]
        Spec[Target Spec: org/name or URL] --> Clone[Clone / Sync to REPOS/org/name]
        Clone --> WT1[Branch Worktree: main]
        Clone --> WT2[Branch Worktree: release/1.0]
    end

    subgraph Collectors [Vulnerability Collectors]
        WT1 & WT2 --> Audit[npm audit + dependency chain tracer]
        Jira[Jira REST Client v2/v3] --> Blend[Vulnerability Blender]
        GH[GitHub Dependabot REST Client] --> Blend
        Audit --> Blend
    end

    subgraph IntermediateReporting [Step 1: Intermediate Reports]
        Blend --> JSONReport[reports/security-report.json]
        Blend --> MDReport[reports/security-report.md]
    end

    subgraph RemediationEngine [Step 2: Remediation Engine]
        JSONReport --> PkgUpdater[package.json Semver & Override Updater]
        PkgUpdater --> LockUpdater[npm install --package-lock-only]
        LockUpdater --> Verify[Post-remediation npm audit verification]
    end

    subgraph CommitPublish [Step 3: Commit & Publish]
        Verify --> CommitGen[Commit Message Generator with Motivating Links]
        CommitGen --> GitCommit[Git Stage & Commit on Branch]
        GitCommit --> Push[Git Push to Remote optional]
    end
```

---

## 3. Directory & Component Structure

```
security-report/
├── package.json               # Node.js ESM configuration & dependencies (commander, semver)
├── agent.md                   # System design rationale and architecture documentation
├── bin/
│   └── sec-remediate.js       # CLI executable entrypoint (chmod +x)
├── src/
│   ├── index.js               # Core library orchestrator (scanRepository, remediateRepository)
│   ├── cli.js                 # Commander CLI definitions (scan, fix, report)
│   ├── config.js              # Configuration loader (env vars, config files, CLI options)
│   ├── core/
│   │   ├── git-manager.js     # Repository cloning to REPOS/, worktree lifecycle & commit management
│   │   ├── dependency-graph.js# Ancestor chain resolution (direct vs. transitive hierarchy)
│   │   ├── blender.js         # Tri-source blending (npm audit + Jira CVEs + Dependabot alerts)
│   │   ├── remediator.js      # package.json and package-lock.json update & verification engine
│   │   └── commit-generator.js# Formats commit messages with CVE, Jira, Dependabot & chain metadata
│   ├── collectors/
│   │   ├── npm-audit.js       # Executes npm audit --json and extracts findings
│   │   ├── jira.js            # Pure JS deterministic Atlassian Jira REST client
│   │   └── dependabot.js      # Pure JS GitHub Dependabot Alerts REST client
│   └── report/
│       ├── json-reporter.js   # Intermediate JSON report generator
│       └── markdown-reporter.js # Human-readable Markdown summary generator
└── test/
    ├── git-manager.test.js    # Unit tests for repo spec parsing and worktrees
    ├── audit-collector.test.js# Unit tests for audit parsing, chain tracing & reporting
    ├── remediator.test.js     # Unit tests for package.json modification and indentation preservation
    ├── external-collectors.test.js # Unit tests for Jira/Dependabot parsing and blending
    └── integration.test.js    # End-to-end multi-branch scan, report, and remediation test
```

---

## 4. Key Design Decisions

### A. Repository Isolation & Multi-Branch Worktrees
- **Problem**: Switching branches in a single working copy invalidates `node_modules`, risks uncommitted changes, and prevents parallel branch analysis.
- **Solution**: The engine clones targets into `REPOS/<org>/<name>` and creates isolated `git worktree` instances for each branch under `<repo>/.worktrees/<sanitized_branch>`.
- **Branch Pointer Handling**: Base repositories are detached upon cloning so all branch names remain available for worktrees. Commits created within worktrees update branch references via `git update-ref refs/heads/<branch> <commitHash>`.

### B. Direct vs. Indirect Ancestor Chain Resolution & 4-Tier Remediation Strategy
- **Problem**: `npm audit` reports hoisted paths (e.g. `node_modules/@xmldom/xmldom`), obscuring the logical parent (e.g. `msw -> @mswjs/interceptors -> @xmldom/xmldom`).
- **Solution**: `src/core/dependency-graph.js` combines `npm ls --all --json` traversal and reverse graph backtracking over `package-lock.json` packages to reconstruct the complete logical ancestry tree down to root `package.json` dependencies.
- **4-Tier Remediation Strategy**:
  1. **`bump-direct`**: Directly updates `package.json` if the package is declared in `dependencies`/`devDependencies`.
  2. **`bump-direct-parent`**: If a direct root parent (e.g. `msw`) has an updated version available that pulls in the safe dependency, updates the direct parent in `package.json`.
  3. **`lockfile-update`**: If the parent package's declared semver range already permits the safe patched version (e.g. parent requires `>=0.7.0 <0.9.0` and `0.8.8` is safe), updates the lockfile directly via `npm install <pkg>@<safeVersion> --package-lock-only` without adding unnecessary `package.json` overrides.
  4. **`package-override`**: Fallback applied if and only if parent ranges strictly forbid the safe version and no direct parent bump is available.

### C. Deterministic JS Clients over Heavy Tooling
- **Decision**: Uses native Node.js `fetch` and ESM modules for Jira and Dependabot REST communication rather than external runtime dependencies or MCP bridges.
- **Jira Integration**: Supports Basic Auth (`email` + `apiToken`) and Personal Access Tokens (PAT Bearer auth) against Jira Cloud (v3) and Jira Server/Data Center (v2).
- **Dependabot Integration**: Uses GitHub REST API (`/repos/{owner}/{repo}/dependabot/alerts`) with bearer token authentication.

### D. 3-Step Remediation Pipeline
1. **Step 1 (Intermediate Report)**: Aggregates findings and generates a single structured JSON schema + Markdown file before touching any code.
2. **Step 2 (Remediation)**:
   - Modifies `package.json` while maintaining exact original file indentation.
   - Runs `npm install --package-lock-only` to update `package-lock.json` atomically.
   - Re-runs `npm audit` in the worktree to verify remaining issues.
3. **Step 3 (Commit Message Generation)**:
   - Formats a conventional commit message with CVE identifiers, Jira ticket URLs, Dependabot alert links, dependency chains, and verification status.

---
### E. Upstream Branch to Downstream Version Translation Table
- **Problem**: Jira CVE tickets are filed against downstream product releases (e.g. `[mta-8.2]`, `[mta-8.1]`, `affectsVersions: ["MTA 8.2.0"]`), while the codebase uses upstream Git branch names (`main`, `release-0.12`, `release-0.11`, `release-0.10`).
- **Solution**: `src/config.js` and `src/core/blender.js` maintain a configurable translation table (`branchMap`) mapping upstream branches to target downstream versions.
- **Matching Rule**: When auditing `release-0.11`, the blender only correlates tickets affecting `8.2.x` / `mta-8.2` (e.g. `MTA-7680`). When auditing `release-0.10`, it correlates tickets affecting `8.1.x` / `mta-8.1` (e.g. `MTA-7679`).

### F. Unified Upstream Branch Grouping across Collectors
- **Problem**: `npm-audit` naturally evaluates branch worktrees individually, but external API collectors (`jira`, `dependabot`) return repository-wide or project-wide lists.
- **Solution**: Both `jira` and `dependabot` collectors now structure their findings into upstream branch sections before reaching the blender:
  - `security-jira-collection.json`: Groups issues into `branches: [{ branch: "release-0.11", mappedVersions: ["8.2"], tickets: [...] }]` plus an `unassigned: [...]` section.
  - `security-dependabot-collection.json`: Groups alerts into `branches: [{ branch: "main", isDefaultBranch: true, alerts: [...] }, { branch: "release-0.11", alerts: [], note: "..." }]`.
  - `security-npm-audit-collection.json`: Contains the raw branch audit results.
- **Benefit**: All debug JSONs and intermediate data structures have a consistent, branch-scoped representation, enabling inspection and deterministic blender correlation.

### G. Jira Remote Link Advisory Resolution & Optimal Safe Version Calculation
- **Problem**: Jira CVE tickets describe downstream flaws and include web links (`remotelink`) to GitHub Security Advisories, but don't natively list upstream npm package fix versions.
- **Solution**:
  1. `src/collectors/jira.js` queries `/rest/api/3/issue/{key}/remotelink` to extract attached GHSA and CVE URLs.
  2. `src/collectors/advisories.js` fetches the advisory data from GitHub Advisory API (and OSV API), resolving `vulnerableVersionRange` and `first_patched_version` (e.g. `qs` $\rightarrow$ `6.16.0`, `js-yaml` $\rightarrow$ `4.3.2`).
  3. `src/core/blender.js` calculates the **optimal target safe version** that satisfies all combined advisories for that package on the target branch.


### H. Upstream Lockfile Assessment for Jira Findings & Dual Direct/Indirect Resolution
- **Problem**: Jira tickets track downstream flaws, but the tool needs to know what is actually installed in the target branch's `package-lock.json`. Furthermore, packages like `js-yaml` may be both directly declared in `package.json` and pulled in transitively by tools like `eslint`.
- **Solution**:
  1. `src/core/dependency-graph.js` (`lookupPackageInstalledInfo`) scans the branch worktree's `package.json` and `package-lock.json` to extract all installed versions (e.g. `3.15.1, 4.3.1`) and ancestor paths.
  2. Detects dual dependency status: `dependencyType: "Direct & Indirect"`.
  3. Formulates a dual resolution plan (`bump-direct-and-lockfile`): updates the `package.json` semver constraint for the direct dependency AND issues lockfile commands (`npm install <pkg>@<safeVersion> --package-lock-only`) to synchronize all transitive instances.


### I. npm Workspaces & Monorepo Direct Dependency Support
- **Problem**: In monorepos using npm workspaces (`workspaces: ["packages/*"]`), direct dependencies can be declared in nested `package.json` files (e.g. `packages/ui/package.json`) rather than only root `package.json`.
- **Solution**:
  1. `src/core/dependency-graph.js` (`findWorkspacePackageJsons`, `getDirectDependencies`) discovers all nested workspace packages.
  2. Dependency checks aggregate direct dependencies across root and all workspaces, tracking the exact declaring workspace and file path.
  3. Remediation (`updatePackageJsonFile`) updates the specific workspace `package.json` file where the dependency is declared.

## 5. Configuration & Environment Variables

| Variable | CLI Flag / Field | Description | Default |
| :--- | :--- | :--- | :--- |
| `SEC_REPO` | `repo` / `[repo]` | Target repository specifier (`org/repo`, URL, or local path) | `null` |
| `SEC_REPOS_DIR` | `--repos-dir` | Directory where repositories are cloned | `./REPOS` |
| `SEC_REPORTS_DIR` | `--reports-dir` | Output directory for reports | `./reports` |
| `SEC_BRANCH_MAP` | `--branch-map` | Upstream branch to downstream version translation table | Built-in MTA map |
| `GITHUB_TOKEN` | `--github-token` | GitHub API Token for Dependabot and private clones | `""` |
| `GITHUB_API_URL` | — | Base URL for GitHub API (Enterprise support) | `https://api.github.com` |
| `JIRA_BASE_URL` | `--jira-base-url` | Atlassian Jira instance URL | `""` |
| `JIRA_EMAIL` | `--jira-email` | Jira user email (for Basic Auth) | `""` |
| `JIRA_API_TOKEN` | `--jira-api-token` | Jira API Token or PAT | `""` |
| `JIRA_PROJECT` | `--jira-project` | Jira Project Key for CVE tickets | `MTA` |
| `JIRA_JQL` | `--jira-jql` | Custom JQL query for Jira ticket retrieval | _Auto-generated_ |
| `SEC_COLLECTORS` | `--collectors` | Comma-separated active collectors (`npm-audit`, `jira`, `dependabot`) | `npm-audit,jira,dependabot` |
| `SEC_DEBUG` | `--debug` | Save raw collector outputs to `security-<name>-collection.json` | `false` |

---

## 6. CLI Commands Reference

```bash
# 1. Scan target branches with all collectors
sec-remediate scan --debug

# 2. Run with JUST Jira (skips npm-audit and Dependabot)
sec-remediate scan --collectors jira

# 3. Run with JUST npm-audit (offline mode, skips Jira and Dependabot)
sec-remediate scan --collectors npm-audit

# 4. Run with specific disabled collectors
sec-remediate scan --no-dependabot

# 5. Dry-run remediation: preview changes and commit message without disk edits
sec-remediate fix --dry-run

# 6. Apply remediation and create Git commits on each branch (Step 2 & Step 3)
sec-remediate fix --commit

# 7. Apply remediation, commit, and push to remote
sec-remediate fix --commit --push
```

---

## 7. Testing & Verification Strategy

The test suite runs via native `node --test` with zero external test runners:
- `test/git-manager.test.js`: Validates URL parsing, local directory handling, and worktree creation/cleanup.
- `test/audit-collector.test.js`: Validates safe version determination, CVE extraction, ancestor chain reconstruction, and report generation.
- `test/remediator.test.js`: Validates indentation preservation, direct updates, and `overrides` additions.
- `test/external-collectors.test.js`: Validates Jira issue parsing, Dependabot alert parsing, and source blending.
- `test/integration.test.js`: Simulates a multi-branch repository lifecycle (scan, report, remediation, and commit creation).
