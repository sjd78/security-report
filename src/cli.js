import { Command } from 'commander';
import { scanRepository, remediateRepository } from './index.js';

export function createCli() {
  const program = new Command();

  program
    .name('sec-remediate')
    .description('Aggregates npm audit, Jira CVEs, and GitHub Dependabot across multiple branches and automates remediation')
    .version('1.0.0');

  program
    .command('scan [repo]')
    .alias('report')
    .description('Scan target repository across branches, blend vulnerability sources, and produce intermediate reports')
    .option('-b, --branches <branches>', 'Comma-separated list of branches to scan (e.g., main,release/1.0)')
    .option('--all-branches', 'Scan all branches found in the repository')
    .option('--repos-dir <path>', 'Custom directory to store cloned repositories (default: REPOS)')
    .option('--reports-dir <path>', 'Custom directory for generated reports (default: reports)')
    .option('--github-token <token>', 'GitHub API token for Dependabot alerts and private clones')
    .option('--jira-base-url <url>', 'Atlassian Jira base URL (e.g., https://org.atlassian.net)')
    .option('--jira-email <email>', 'Jira user email address')
    .option('--jira-api-token <token>', 'Jira API token or Personal Access Token')
    .option('--jira-project <project>', 'Jira Project Key (default: MTA)')
    .option('--jira-jql <query>', 'Custom JQL query for Jira ticket retrieval')
    .option('--branch-map <mapping>', 'Branch to downstream version mapping (e.g. main=8.3,release-0.11=8.2,release-0.10=8.1)')
    .option('--collectors <list>', 'Comma-separated collectors to enable (e.g. jira, npm-audit, dependabot)')
    .option('--no-npm-audit', 'Disable npm audit collector')
    .option('--no-jira', 'Disable Jira collector')
    .option('--no-dependabot', 'Disable GitHub Dependabot collector')
    .option('--no-overrides', 'Leave override-only findings for manual remediation planning')
    .option('--debug', 'Save raw collector outputs to security-<name>-collection.json')
    .action(async (repo, options) => {
      try {
        await scanRepository(repo, options);
      } catch (err) {
        console.error(`\n❌ [Scan Error] ${err.message}`);
        process.exit(1);
      }
    });

  for (const [name, createPr] of [['fix', false], ['pr', true]]) {
    const command = program
      .command(`${name} [repo]`)
      .description(createPr
        ? 'Execute a reviewed remediation plan and publish verified changes as pull requests'
        : 'Execute a reviewed remediation plan in isolated remediation branches')
      .requiredOption('--plan <path>', 'Saved security-remediation-plan.json to execute; never rescans')
      .option('-b, --branches <branches>', 'Select comma-separated branches from the saved plan')
      .option('--packages <packages>', 'Select comma-separated vulnerable package names within the selected branches')
      .option('--fix-types <types>', 'Select safe-fix, override-required, parent-upgrade, or breaking-upgrade (comma-separated)')
      .option('--no-breaking', 'Exclude breaking or unknown-risk upgrades; verify actual versions before publishing')
      .option('--dry-run', 'Validate the plan and preview actions without applying or publishing', false)
      .option('--no-overrides', 'Reject a plan that requires npm overrides')
      .option('--repos-dir <path>', 'Directory for cloned repositories')
      .option('--reports-dir <path>', 'Directory for execution results')
      .option('--github-token <token>', 'GitHub token for private Git access and PR publishing')
      .option('--fork-repo <owner/repo>', 'Push remediation branches to this fork; keep PRs targeted at the scanned upstream repository')
      .option('--pr-title-template <text>', 'Title using {targetBranch}, {targetPackages}, and {summary}')
      .action(async (repo, options) => {
        try {
          await remediateRepository(repo, { ...options, createPr });
        } catch (error) {
          console.error(`\n[${createPr ? 'PR' : 'Remediation'} Error] ${error.message}`);
          process.exitCode = 1;
        }
      });
    if (!createPr) {
      command.alias('remediate')
        .option('--commit', 'Commit verified changes on a remediation branch', false)
        .option('--push', 'Push the remediation branch; requires --commit', false);
    }
  }

  return program;
}
