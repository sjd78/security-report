import path from 'node:path';
import fs from 'node:fs';

export function parseBranchMap(mapInput) {
  if (!mapInput) return {};
  if (typeof mapInput === 'object') return mapInput;

  // Try JSON parse
  if (typeof mapInput === 'string') {
    try {
      return JSON.parse(mapInput);
    } catch {
      // Parse key=val,key2=val2 format (e.g., "main=8.3,release-0.11=8.2,release-0.10=8.1")
      const result = {};
      const pairs = mapInput.split(',').map((p) => p.trim()).filter(Boolean);
      for (const pair of pairs) {
        const [k, v] = pair.split('=').map((s) => s.trim());
        if (k && v) {
          result[k] = v.split('|').map((s) => s.trim());
        }
      }
      return result;
    }
  }

  return {};
}

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

  const rawBranchMap = options.branchMap || process.env.SEC_BRANCH_MAP || fileConfig.branchMap || {
    main: ['8.3.x', '8.3', 'mta-8.3', 'MTA 8.3'],
    'release-0.12': ['8.3.x', '8.3', 'mta-8.3', 'MTA 8.3'],
    'release-0.11': ['8.2.x', '8.2', 'mta-8.2', 'MTA 8.2'],
    'release-0.10': ['8.1.x', '8.1', 'mta-8.1', 'MTA 8.1'],
  };

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
      project: options.jiraProject || process.env.JIRA_PROJECT || fileConfig.jira?.project || 'MTA',
      jql: options.jiraJql || process.env.JIRA_JQL || fileConfig.jira?.jql || '',
    },
    branchMap: parseBranchMap(rawBranchMap),
    defaultBranches: options.branches || fileConfig.branches || ['main'],
    semverUpdateType: options.semverUpdateType || fileConfig.semverUpdateType || 'minor',
    allowOverrides: options.allowOverrides ?? fileConfig.allowOverrides ?? true,
    ...options,
  };
}
