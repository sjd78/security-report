import path from 'node:path';
import fs from 'node:fs';

export function loadConfig(options = {}) {
  const cwd = process.cwd();
  let fileConfig = {};

  const configPaths = [
    path.resolve(cwd, '.security-report.json'),
    path.resolve(cwd, 'security-report.config.json'),
  ];

  for (const cp of configPaths) {
    if (fs.existsSync(cp)) {
      try {
        fileConfig = JSON.parse(fs.readFileSync(cp, 'utf8'));
        break;
      } catch (err) {
        console.warn(`[Config] Warning: Failed to parse ${cp}: ${err.message}`);
      }
    }
  }

  const reposDir = path.resolve(
    cwd,
    options.reposDir || process.env.SEC_REPOS_DIR || fileConfig.reposDir || 'REPOS'
  );

  const reportsDir = path.resolve(
    cwd,
    options.reportsDir || process.env.SEC_REPORTS_DIR || fileConfig.reportsDir || 'reports'
  );

  return {
    reposDir,
    reportsDir,
    gitProtocol: options.gitProtocol || process.env.GIT_PROTOCOL || fileConfig.gitProtocol || 'https',
    githubToken: options.githubToken || process.env.GITHUB_TOKEN || fileConfig.githubToken || '',
    githubApiUrl: options.githubApiUrl || process.env.GITHUB_API_URL || fileConfig.githubApiUrl || 'https://api.github.com',
    jira: {
      baseUrl: options.jiraBaseUrl || process.env.JIRA_BASE_URL || fileConfig.jira?.baseUrl || '',
      email: options.jiraEmail || process.env.JIRA_EMAIL || fileConfig.jira?.email || '',
      apiToken: options.jiraApiToken || process.env.JIRA_API_TOKEN || fileConfig.jira?.apiToken || '',
      project: options.jiraProject || process.env.JIRA_PROJECT || fileConfig.jira?.project || 'SEC',
      jql: options.jiraJql || process.env.JIRA_JQL || fileConfig.jira?.jql || '',
    },
    defaultBranches: options.branches || fileConfig.branches || ['main'],
    semverUpdateType: options.semverUpdateType || fileConfig.semverUpdateType || 'minor', // or 'patch', 'latest'
    allowOverrides: options.allowOverrides ?? fileConfig.allowOverrides ?? true,
    ...options,
  };
}
