import path from 'node:path';
import { loadConfig } from './config.js';
import {
  ensureRepo,
  listBranches,
  withWorktree,
  stageAndCommit,
  pushBranch,
} from './core/git-manager.js';
import { collectNpmAudit } from './collectors/npm-audit.js';
import { fetchJiraCveTickets } from './collectors/jira.js';
import { fetchDependabotAlerts } from './collectors/dependabot.js';
import { blendVulnerabilitySources } from './core/blender.js';
import { generateJsonReport, writeJsonReport } from './report/json-reporter.js';
import { generateMarkdownReport, writeMarkdownReport } from './report/markdown-reporter.js';
import { remediateBranch } from './core/remediator.js';
import { generateCommitMessage } from './core/commit-generator.js';

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
  let branchesToScan = config.defaultBranches;
  if (cliOptions.branches) {
    branchesToScan = String(cliOptions.branches).split(',').map((b) => b.trim()).filter(Boolean);
  } else if (cliOptions.allBranches) {
    branchesToScan = await listBranches(repoInfo.repoPath);
  }

  console.log(`🌿 [Scan] Target branches (${branchesToScan.length}): ${branchesToScan.join(', ')}`);

  // Fetch external sources in parallel
  console.log(`📡 [Scan] Fetching Jira CVE tickets and GitHub Dependabot alerts...`);
  const [jiraTickets, dependabotAlerts] = await Promise.all([
    fetchJiraCveTickets(config, { maxResults: 100 }),
    fetchDependabotAlerts({
      org: repoInfo.org,
      name: repoInfo.name,
      githubToken: config.githubToken,
      githubApiUrl: config.githubApiUrl,
    }),
  ]);

  console.log(`ℹ️ [Scan] Fetched ${jiraTickets.length} Jira CVE ticket(s) and ${dependabotAlerts.length} Dependabot alert(s)`);

  // Run npm audit across all branch worktrees
  const rawBranchReports = [];
  for (const branch of branchesToScan) {
    console.log(`🔬 [Scan] Inspecting branch: ${branch}`);
    try {
      const branchReport = await withWorktree(repoInfo.repoPath, branch, async (worktreeDir) => {
        return await collectNpmAudit(worktreeDir, branch);
      });
      rawBranchReports.push(branchReport);
    } catch (err) {
      console.warn(`⚠️ [Scan] Failed to audit branch ${branch}: ${err.message}`);
      rawBranchReports.push({
        branch,
        error: err.message,
        summary: { critical: 0, high: 0, moderate: 0, low: 0, total: 0 },
        vulnerabilities: [],
      });
    }
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

  console.log(`\n📄 [Scan] Intermediate JSON report generated: ${jsonPath}`);
  console.log(`📝 [Scan] Human-readable Markdown report generated: ${mdPath}`);

  return {
    config,
    repository: repoInfo,
    report,
    jsonPath,
    mdPath,
  };
}

export async function remediateRepository(repoSpec, cliOptions = {}) {
  const initialConfig = loadConfig(cliOptions);
  const targetRepo = repoSpec || initialConfig.repo;
  if (!targetRepo) {
    throw new Error('No target repository specified. Please provide a repository (e.g. "org/repo") or define "repo" in .security-report.json');
  }

  // Step 1: Scan and create intermediate report
  const scanResult = await scanRepository(targetRepo, cliOptions);
  const { config, repository, report } = scanResult;

  const isDryRun = Boolean(cliOptions.dryRun);
  const shouldCommit = Boolean(cliOptions.commit);
  const shouldPush = Boolean(cliOptions.push);

  console.log(`\n🛠️ [Remediate] Starting remediation (Mode: ${isDryRun ? 'DRY-RUN' : shouldCommit ? 'COMMIT' : 'APPLY-ONLY'})...`);

  const remediationSummary = [];

  for (const branchReport of report.branches) {
    const branch = branchReport.branch;
    const vulnCount = (branchReport.vulnerabilities || []).length;

    if (vulnCount === 0) {
      console.log(`✨ [Remediate] Branch \`${branch}\` is clean. Skipping.`);
      continue;
    }

    console.log(`\n🚀 [Remediate] Processing branch \`${branch}\` (${vulnCount} vulnerabilities)...`);

    await withWorktree(repository.repoPath, branch, async (worktreeDir) => {
      // Step 2: Apply package.json and lockfile remediations
      const remResult = await remediateBranch(worktreeDir, branchReport, {
        dryRun: isDryRun,
        allowOverrides: config.allowOverrides,
      });

      console.log(`   - Applied changes: ${remResult.appliedChanges.length}`);
      console.log(`   - Resolved vulnerabilities: ${remResult.resolved.length}`);
      console.log(`   - Remaining vulnerabilities: ${remResult.remaining.length}`);

      // Step 3: Generate commit message
      const commitMessage = generateCommitMessage(branch, remResult);

      if (isDryRun) {
        console.log(`\n[DRY RUN] Would commit with message:\n--------------------\n${commitMessage}\n--------------------`);
        remediationSummary.push({ branch, remResult, committed: false, commitMessage });
        return;
      }

      if (shouldCommit && remResult.appliedChanges.length > 0) {
        console.log(`📝 [Commit] Creating Git commit on branch \`${branch}\`...`);
        const commitRes = await stageAndCommit(worktreeDir, {
          message: commitMessage,
          files: ['package.json', 'package-lock.json'],
        });

        if (commitRes.committed) {
          console.log(`✅ [Commit] Created commit ${commitRes.commitHash.substring(0, 7)} on \`${branch}\``);

          if (shouldPush) {
            console.log(`⬆️ [Push] Pushing \`${branch}\` to remote...`);
            await pushBranch(worktreeDir, branch);
            console.log(`✅ [Push] Successfully pushed \`${branch}\``);
          }
        }

        remediationSummary.push({ branch, remResult, commit: commitRes, commitMessage });
      } else {
        remediationSummary.push({ branch, remResult, committed: false, commitMessage });
      }
    });
  }

  console.log(`\n🎉 [Remediate] Completed remediation across all branches!`);
  return {
    scanResult,
    remediationSummary,
  };
}
