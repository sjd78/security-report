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
    .description('Scan target repository across branches, blend vulnerability sources, and produce intermediate reports')
    .option('-b, --branches <branches>', 'Comma-separated list of branches to scan (e.g., main,release/1.0)')
    .option('--all-branches', 'Scan all branches found in the repository')
    .option('--repos-dir <path>', 'Custom directory to store cloned repositories', 'REPOS')
    .option('--reports-dir <path>', 'Custom directory for generated reports', 'reports')
    .option('--github-token <token>', 'GitHub API token for Dependabot alerts and private clones')
    .option('--jira-base-url <url>', 'Atlassian Jira base URL (e.g., https://org.atlassian.net)')
    .option('--jira-email <email>', 'Jira user email address')
    .option('--jira-api-token <token>', 'Jira API token or Personal Access Token')
    .option('--jira-project <project>', 'Jira Project Key (default: SEC)', 'SEC')
    .option('--jira-jql <query>', 'Custom JQL query for Jira ticket retrieval')
    .option('--branch-map <mapping>', 'Branch to downstream version mapping (e.g. main=8.3,release-0.11=8.2,release-0.10=8.1)')
    .option('--collectors <list>', 'Comma-separated collectors to enable (e.g. jira, npm-audit, dependabot)')
    .option('--no-npm-audit', 'Disable npm audit collector')
    .option('--no-jira', 'Disable Jira collector')
    .option('--no-dependabot', 'Disable GitHub Dependabot collector')
    .option('--debug', 'Save raw collector outputs to security-<name>-collection.json', false)
    .action(async (repo, options) => {
      try {
        await scanRepository(repo, options);
      } catch (err) {
        console.error(`\n❌ [Scan Error] ${err.message}`);
        process.exit(1);
      }
    });

  program
    .command('fix [repo]')
    .alias('remediate')
    .description('Remediate vulnerabilities on target repository branches (package.json + lockfile + commit)')
    .option('-b, --branches <branches>', 'Comma-separated list of branches to remediate')
    .option('--all-branches', 'Remediate all branches found in the repository')
    .option('--dry-run', 'Preview changes and commit message without modifying files or committing', false)
    .option('--commit', 'Create git commits on the target branches with motivating links', false)
    .option('--push', 'Push created commits to remote repository', false)
    .option('--no-overrides', 'Do not insert npm overrides into package.json')
    .option('--repos-dir <path>', 'Custom directory to store cloned repositories', 'REPOS')
    .option('--reports-dir <path>', 'Custom directory for generated reports', 'reports')
    .option('--github-token <token>', 'GitHub API token')
    .option('--jira-base-url <url>', 'Jira base URL')
    .option('--jira-email <email>', 'Jira user email')
    .option('--jira-api-token <token>', 'Jira API token')
    .option('--jira-project <project>', 'Jira Project Key', 'SEC')
    .option('--jira-jql <query>', 'Custom JQL query for Jira ticket retrieval')
    .option('--branch-map <mapping>', 'Branch to downstream version mapping (e.g. main=8.3,release-0.11=8.2,release-0.10=8.1)')
    .option('--collectors <list>', 'Comma-separated collectors to enable (e.g. jira, npm-audit, dependabot)')
    .option('--no-npm-audit', 'Disable npm audit collector')
    .option('--no-jira', 'Disable Jira collector')
    .option('--no-dependabot', 'Disable GitHub Dependabot collector')
    .option('--debug', 'Save raw collector outputs to security-<name>-collection.json', false)
    .action(async (repo, options) => {
      try {
        await remediateRepository(repo, options);
      } catch (err) {
        console.error(`\n❌ [Remediation Error] ${err.message}`);
        process.exit(1);
      }
    });

  program
    .command('report [repo]')
    .description('Alias for scan')
    .option('-b, --branches <branches>', 'Comma-separated list of branches')
    .option('--reports-dir <path>', 'Custom directory for generated reports', 'reports')
    .option('--collectors <list>', 'Comma-separated collectors to enable (e.g. jira, npm-audit, dependabot)')
    .option('--no-npm-audit', 'Disable npm audit collector')
    .option('--no-jira', 'Disable Jira collector')
    .option('--no-dependabot', 'Disable GitHub Dependabot collector')
    .option('--debug', 'Save raw collector outputs to security-<name>-collection.json', false)
    .action(async (repo, options) => {
      try {
        await scanRepository(repo, options);
      } catch (err) {
        console.error(`\n❌ [Report Error] ${err.message}`);
        process.exit(1);
      }
    });

  return program;
}
