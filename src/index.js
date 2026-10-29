import path from 'node:path';
import fs from 'node:fs';
import { loadConfig } from './config.js';
import {
  ensureRepo,
  listBranches,
  withWorktree,
  execGit,
} from './core/git-manager.js';
import { readPackageJson, readPackageLock, runNpmLs, findWorkspacePackageJsons, loadArboristTree } from './core/dependency-graph.js';
import { collectNpmAudit } from './collectors/npm-audit.js';
import { fetchJiraCveTickets, groupJiraTicketsByBranch } from './collectors/jira.js';
import { fetchDependabotAlerts, groupDependabotAlertsByBranch } from './collectors/dependabot.js';
import { blendVulnerabilitySources } from './core/blender.js';
import { generateJsonReport, writeJsonReport } from './report/json-reporter.js';
import { writeMarkdownReport } from './report/markdown-reporter.js';
import { generateRemediationPlan, writeRemediationPlan } from './report/remediation-reporter.js';
import { readRemediationPlan, executeRemediationPlan } from './core/plan-executor.js';

export function saveDebugCollection(collectorName, data, reportsDir) {
  fs.mkdirSync(reportsDir, { recursive: true });
  const filename = `security-${collectorName}-collection.json`;
  const filePath = path.resolve(reportsDir, filename);
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
  console.log(`🐛 [Debug] Saved ${collectorName} collection: ${filePath}`);
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
    ? fetchJiraCveTickets(config, { maxResults: 100, branches: branchesToScan })
    : Promise.resolve(groupJiraTicketsByBranch([], branchesToScan, config.branchMap));

  const dependabotPromise = config.collectors.dependabot
    ? fetchDependabotAlerts({
        org: repoInfo.org,
        name: repoInfo.name,
        githubToken: config.githubToken,
        githubApiUrl: config.githubApiUrl,
        branches: branchesToScan,
        defaultBranch: branchesToScan[0] || 'main',
      })
    : Promise.resolve(groupDependabotAlertsByBranch([], branchesToScan));

  const [jiraTickets, dependabotAlerts] = await Promise.all([jiraPromise, dependabotPromise]);

  const jiraCount = jiraTickets.totalTickets ?? (Array.isArray(jiraTickets) ? jiraTickets.length : 0);
  const dependabotCount = dependabotAlerts.totalAlerts ?? (Array.isArray(dependabotAlerts) ? dependabotAlerts.length : 0);
  if (config.collectors.jira || config.collectors.dependabot) {
    console.log(`📡 [Scan] Fetched ${jiraCount} Jira CVE ticket(s) and ${dependabotCount} Dependabot alert(s) across ${branchesToScan.length} branch(es)`);
  }

  // Run branch inspection and audit
  const rawBranchReports = [];
  for (const branch of branchesToScan) {
    console.log(`🔬 [Scan] Inspecting branch: ${branch}`);
    try {
      const branchReport = await withWorktree(repoInfo.repoPath, branch, async (worktreeDir) => {
        const { stdout: baseCommit } = await execGit(['rev-parse', 'HEAD'], worktreeDir);
        const pkgJson = readPackageJson(worktreeDir);
        const pkgLock = readPackageLock(worktreeDir);
        const workspaces = findWorkspacePackageJsons(worktreeDir, pkgJson);

        let arboristTree = null;
        try {
          arboristTree = await loadArboristTree({ dir: worktreeDir });
        } catch {
          // ignore
        }

        let npmLsData = null;
        if (!arboristTree) {
          try {
            npmLsData = await runNpmLs(worktreeDir);
          } catch {
            // ignore
          }
        }

        const audit = config.collectors.npmAudit
          ? await collectNpmAudit(worktreeDir, branch, {
              githubToken: config.githubToken,
              githubApiUrl: config.githubApiUrl,
              arboristTree,
            })
          : { summary: { critical: 0, high: 0, moderate: 0, low: 0, total: 0 }, vulnerabilities: [] };

        return {
          ...audit,
          branch,
          baseCommit,
          pkgJson,
          pkgLock,
          npmLsData,
          workspaces,
          arboristTree,
          worktreeDir,
        };
      }, { snapshot: true });
      rawBranchReports.push(branchReport);
    } catch (err) {
      console.warn(`⚠️ [Scan] Failed to inspect branch ${branch}: ${err.message}`);
      rawBranchReports.push({
        branch,
        error: err.message,
        summary: { critical: 0, high: 0, moderate: 0, low: 0, total: 0 },
        vulnerabilities: [],
      });
    }
  }
  // Save raw collector outputs in debug mode
  if (config.debug) {
    saveDebugCollection('jira', jiraTickets, config.reportsDir);
    saveDebugCollection('dependabot', dependabotAlerts, config.reportsDir);
    saveDebugCollection('npm-audit', rawBranchReports, config.reportsDir);
  }
  // Blend sources
  console.log(`🔄 [Scan] Blending audit findings with Jira and Dependabot...`);
  const blendedBranches = blendVulnerabilitySources(rawBranchReports, {
    jiraTickets,
    dependabotAlerts,
    branchMap: config.branchMap,
  });

  const report = generateJsonReport(repoInfo, blendedBranches);

  // Write reports
  const jsonPath = writeJsonReport(report, config.reportsDir);
  const mdPath = writeMarkdownReport(report, config.reportsDir);
  const remediationPlan = generateRemediationPlan(report, { allowOverrides: config.allowOverrides });
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
