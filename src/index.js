import path from 'node:path';
import fs from 'node:fs';
import { loadConfig } from './config.js';
import {
  ensureRepo,
  listBranches,
  withWorktree,
  execGit,
} from './core/git-manager.js';
import { readPackageJson, readPackageLock, runNpmLs, findWorkspacePackageJsons, loadArboristTree, getPackageInstances } from './core/dependency-graph.js';
import { isVersionSafe } from './core/advisory-evidence.js';
import { fetchPublishedVersions } from './collectors/npm-versions.js';
import { collectNpmAudit, groupNpmAuditByBranch } from './collectors/npm-audit.js';
import { fetchJiraCveTickets, groupJiraTicketsByBranch } from './collectors/jira.js';
import { fetchDependabotAlerts, groupDependabotAlertsByBranch } from './collectors/dependabot.js';
import { blendVulnerabilitySources } from './core/blender.js';
import { generateJsonReport, writeJsonReport } from './report/json-reporter.js';
import { writeMarkdownReport } from './report/markdown-reporter.js';
import { generateRemediationPlan, writeRemediationPlan } from './report/remediation-reporter.js';
import { readRemediationPlan, executeRemediationPlan } from './core/plan-executor.js';

export function saveDebugCollection(collectorName, data, reportsDir) {
  fs.mkdirSync(reportsDir, { recursive: true });
  const filename = `debug-collection-${collectorName}.json`;
  const filePath = path.resolve(reportsDir, filename);
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
  console.log(`🐛 [Debug] Saved ${collectorName} collection: ${filePath}`);
  return filePath;
}

export function saveDebugBlended(repository, branches, reportsDir) {
  const projection = {
    repository,
    branches: branches.map(({ branch, baseCommit, error, vulnerabilities = [] }) => ({
      branch,
      ...(baseCommit !== undefined ? { baseCommit } : {}),
      ...(error !== undefined ? { error } : {}),
      packages: vulnerabilities.map(({ packageName, findings, affectedVersions }) => ({
        packageName,
        findings,
        affectedVersions,
      })),
    })),
  };
  fs.mkdirSync(reportsDir, { recursive: true });
  const filePath = path.resolve(reportsDir, 'debug-blended.json');
  fs.writeFileSync(filePath, JSON.stringify(projection, null, 2), 'utf8');
  console.log(`🐛 [Debug] Saved blended evidence: ${filePath}`);
  return filePath;
}

export async function scanRepository(repoSpec, cliOptions = {}) {
  const config = loadConfig(cliOptions);
  const targetRepo = repoSpec || config.repo;
  if (!targetRepo) {
    throw new Error('No target repository specified. Please provide a repository (e.g. "org/repo") or define "repo" in .security-report.json');
  }

  console.log(`\n🔍 [Scan] Target repository: ${targetRepo}`);
  console.log(`📁 [Scan] REPOS directory: ${config.reposDir}`);

  // Step 1: Ensure repository in REPOS/
  const repoInfo = await ensureRepo(targetRepo, config);
  console.log(`✅ [Scan] Local repo ready at: ${repoInfo.repoPath}`);
  const repository = { org: repoInfo.org, name: repoInfo.name, fullName: repoInfo.fullName };

  // Determine branches to scan
  let branchesToScan = Array.isArray(config.defaultBranches)
    ? config.defaultBranches
    : String(config.defaultBranches).split(',').map((branch) => branch.trim()).filter(Boolean);
  if (cliOptions.branches) {
    branchesToScan = String(cliOptions.branches).split(',').map((b) => b.trim()).filter(Boolean);
  } else if (cliOptions.allBranches) {
    branchesToScan = await listBranches(repoInfo.repoPath);
  }

  console.log(`🌿 [Scan] Target branches (${branchesToScan.length}): ${branchesToScan.join(', ')}`);

  const enabledCollectors = [];
  if (config.collectors.npmAudit) enabledCollectors.push('npm-audit');
  if (config.collectors.jira) enabledCollectors.push('jira');
  if (config.collectors.dependabot) enabledCollectors.push('dependabot');
  console.log(`🔌 [Scan] Enabled collectors: ${enabledCollectors.join(', ') || 'none'}`);

  // Fetch external sources conditionally
  const jiraPromise = config.collectors.jira
    ? fetchJiraCveTickets(config, { maxResults: 100, branches: branchesToScan, repository })
    : Promise.resolve(groupJiraTicketsByBranch([], branchesToScan, config.branchMap, repository));

  const dependabotPromise = config.collectors.dependabot
    ? fetchDependabotAlerts({
        org: repoInfo.org,
        name: repoInfo.name,
        githubToken: config.githubToken,
        githubApiUrl: config.githubApiUrl,
        branches: branchesToScan,
        repository,
      })
    : Promise.resolve(groupDependabotAlertsByBranch([], branchesToScan, 'main', repository));

  const [jiraTickets, dependabotAlerts] = await Promise.all([jiraPromise, dependabotPromise]);

  const jiraCount = jiraTickets.totalTickets ?? (Array.isArray(jiraTickets) ? jiraTickets.length : 0);
  const dependabotCount = dependabotAlerts.totalAlerts ?? (Array.isArray(dependabotAlerts) ? dependabotAlerts.length : 0);
  if (config.collectors.jira || config.collectors.dependabot) {
    console.log(`📡 [Scan] Fetched ${jiraCount} Jira CVE ticket(s) and ${dependabotCount} Dependabot alert(s) across ${branchesToScan.length} branch(es)`);
  }

  // Blend and query registries while each branch worktree and its npm configuration are live.
  const rawBranchReports = [];
  const blendedBranches = [];
  const publishedVersionsByBranch = new Map();
  const blenderOptions = { jiraTickets, dependabotAlerts, branchMap: config.branchMap };
  for (const branch of branchesToScan) {
    console.log(`🔬 [Scan] Inspecting branch: ${branch}`);
    try {
      const result = await withWorktree(repoInfo.repoPath, branch, async (worktreeDir) => {
        const { stdout: baseCommit } = await execGit(['rev-parse', 'HEAD'], worktreeDir);
        const pkgJson = readPackageJson(worktreeDir);
        const pkgLock = readPackageLock(worktreeDir);
        const workspaces = findWorkspacePackageJsons(worktreeDir, pkgJson);
        let arboristTree = null;
        try { arboristTree = await loadArboristTree({ dir: worktreeDir }); } catch { /* unavailable */ }

        let npmLsData = null;
        if (!arboristTree) {
          try { npmLsData = await runNpmLs(worktreeDir); } catch { /* unavailable */ }
        }

        const audit = config.collectors.npmAudit
          ? await collectNpmAudit(worktreeDir, branch, {
              githubToken: config.githubToken,
              githubApiUrl: config.githubApiUrl,
              arboristTree,
            })
          : { summary: { critical: 0, high: 0, moderate: 0, low: 0, total: 0 }, vulnerabilities: [] };
        const raw = {
          ...audit, branch, baseCommit, pkgJson, pkgLock, npmLsData, workspaces, arboristTree, worktreeDir,
        };
        const blended = blendVulnerabilitySources([raw], blenderOptions)[0];
        const packagesNeedingCatalog = new Set();
        for (const vulnerability of blended.vulnerabilities || []) {
          const packageName = vulnerability.packageName;
          if (!packageName) continue;
          const findings = vulnerability.findings;
          if (getPackageInstances(packageName, raw).some((instance) => isVersionSafe(instance.installedVersion, findings) !== true)) {
            packagesNeedingCatalog.add(packageName);
          }
        }
        const versions = await fetchPublishedVersions(worktreeDir, [...packagesNeedingCatalog]);
        return { raw, blended, versions };
      }, { snapshot: true });
      rawBranchReports.push(result.raw);
      blendedBranches.push(result.blended);
      publishedVersionsByBranch.set(branch, result.versions);
    } catch (err) {
      console.warn(`⚠️ [Scan] Failed to inspect branch ${branch}: ${err.message}`);
      const failed = {
        branch,
        error: err.message,
        summary: { critical: 0, high: 0, moderate: 0, low: 0, total: 0 },
        vulnerabilities: [],
      };
      rawBranchReports.push(failed);
      blendedBranches.push(failed);
      publishedVersionsByBranch.set(branch, new Map());
    }
  }

  if (config.debug) {
    saveDebugCollection('jira', jiraTickets, config.reportsDir);
    saveDebugCollection('dependabot', dependabotAlerts, config.reportsDir);
    saveDebugCollection('npm-audit', groupNpmAuditByBranch(rawBranchReports, repository), config.reportsDir);
    saveDebugBlended(repository, blendedBranches, config.reportsDir);
  }
  console.log(`🔄 [Scan] Blended branch findings and resolved published version catalogs.`);
  const report = generateJsonReport(repoInfo, blendedBranches);

  const jsonPath = writeJsonReport(report, config.reportsDir);
  const mdPath = writeMarkdownReport(report, config.reportsDir);
  const remediationPlan = generateRemediationPlan(report, {
    allowOverrides: config.allowOverrides,
    publishedVersionsByBranch,
  });
  const remediationPlanPath = writeRemediationPlan(remediationPlan, config.reportsDir);


  console.log(`\n📄 [Scan] Intermediate JSON report generated: ${jsonPath}`);
  console.log(`📝 [Scan] Human-readable Markdown report generated: ${mdPath}`);
  console.log(`Remediation plan generated: ${remediationPlanPath}`);

  return {
    config,
    repository: repoInfo,
    report,
    jsonPath,
    mdPath,
    remediationPlan,
    remediationPlanPath,
  };
}

export async function remediateRepository(repoSpec, cliOptions = {}) {
  const config = loadConfig(cliOptions);
  const planPath = cliOptions.plan;
  if (!planPath) throw new Error('A saved remediation plan is required. Run scan, review the plan, then use --plan <path>.');
  const plan = readRemediationPlan(planPath);
  return executeRemediationPlan(plan, {
    ...config,
    repo: repoSpec || config.repo || plan.repository.path,
  });
}
