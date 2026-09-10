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

export function parseCollectorSettings(options = {}, fileConfig = {}) {
  let npmAudit = true;
  let jira = true;
  let dependabot = true;

  // 1. Config file settings
  if (fileConfig.collectors) {
    if (Array.isArray(fileConfig.collectors)) {
      const set = new Set(fileConfig.collectors.map((c) => String(c).toLowerCase().replace(/[-_]/g, '')));
      npmAudit = set.has('npmaudit');
      jira = set.has('jira');
      dependabot = set.has('dependabot');
    } else if (typeof fileConfig.collectors === 'object') {
      if (fileConfig.collectors.npmAudit !== undefined) npmAudit = Boolean(fileConfig.collectors.npmAudit);
      if (fileConfig.collectors.jira !== undefined) jira = Boolean(fileConfig.collectors.jira);
      if (fileConfig.collectors.dependabot !== undefined) dependabot = Boolean(fileConfig.collectors.dependabot);
    }
  }

  // 2. Env variable override (e.g. SEC_COLLECTORS="jira")
  const envCollectors = process.env.SEC_COLLECTORS;
  if (envCollectors) {
    const set = new Set(envCollectors.split(',').map((c) => c.trim().toLowerCase().replace(/[-_]/g, '')));
    npmAudit = set.has('npmaudit');
    jira = set.has('jira');
    dependabot = set.has('dependabot');
  }

  // 3. CLI --collectors flag (e.g. --collectors jira or --collectors npm-audit,jira)
  if (options.collectors) {
    const list = Array.isArray(options.collectors) ? options.collectors : String(options.collectors).split(',');
    const set = new Set(list.map((c) => c.trim().toLowerCase().replace(/[-_]/g, '')));
    npmAudit = set.has('npmaudit');
    jira = set.has('jira');
    dependabot = set.has('dependabot');
  }

  // 4. Individual boolean flags (e.g. --no-jira, --no-npm-audit, --no-dependabot)
  if (options.npmAudit === false || options.noNpmAudit === true) npmAudit = false;
  if (options.jira === false || options.noJira === true) jira = false;
  if (options.dependabot === false || options.noDependabot === true) dependabot = false;

  return {
    npmAudit,
    jira,
    dependabot,
  };
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

  const repo =
    options.repo ||
    options.repository ||
    process.env.SEC_REPO ||
    fileConfig.repo ||
    fileConfig.repository ||
    null;

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

  const collectors = parseCollectorSettings(options, fileConfig);

  const rawBaseUrl = options.jiraBaseUrl !== undefined
    ? options.jiraBaseUrl
    : (fileConfig.jira?.baseUrl !== undefined ? fileConfig.jira.baseUrl : (process.env.JIRA_BASE_URL || ''));

  const rawApiToken = options.jiraApiToken !== undefined
    ? options.jiraApiToken
    : (fileConfig.jira?.apiToken !== undefined ? fileConfig.jira.apiToken : (process.env.JIRA_API_TOKEN || ''));

  const rawEmail = options.jiraEmail !== undefined
    ? options.jiraEmail
    : (fileConfig.jira?.email !== undefined ? fileConfig.jira.email : (process.env.JIRA_EMAIL || ''));

  const jira = {
    baseUrl: String(rawBaseUrl || '').trim(),
    email: String(rawEmail || '').trim(),
    apiToken: String(rawApiToken || '').trim(),
    project: options.jiraProject || process.env.JIRA_PROJECT || fileConfig.jira?.project || 'MTA',
    jql: options.jiraJql || process.env.JIRA_JQL || fileConfig.jira?.jql || '',
  };

  // If Jira collector is enabled but configuration is incomplete, disable it and log notice
  if (collectors.jira) {
    const missingFields = [];
    if (!jira.baseUrl) missingFields.push('baseUrl (or JIRA_BASE_URL)');
    if (!jira.apiToken) missingFields.push('apiToken (or JIRA_API_TOKEN)');

    if (missingFields.length > 0) {
      collectors.jira = false;
      if (!options.silent) {
        console.warn(`⚠️ [Config] Notice: Jira collector is enabled but Jira configuration is incomplete (missing ${missingFields.join(', ')}). Disabling Jira collector.`);
      }
    }
  }

  const rawGhToken = options.githubToken !== undefined
    ? options.githubToken
    : (fileConfig.githubToken !== undefined ? fileConfig.githubToken : (process.env.GITHUB_TOKEN || ''));

  const githubToken = String(rawGhToken || '').trim();

  return {
    ...options,
    debug: Boolean(options.debug ?? (process.env.SEC_DEBUG === 'true' || fileConfig.debug || false)),
    repo,
    reposDir,
    reportsDir,
    collectors,
    gitProtocol: options.gitProtocol || process.env.GIT_PROTOCOL || fileConfig.gitProtocol || 'https',
    githubToken,
    githubApiUrl: options.githubApiUrl || process.env.GITHUB_API_URL || fileConfig.githubApiUrl || 'https://api.github.com',
    jira,
    branchMap: parseBranchMap(rawBranchMap),
    defaultBranches: options.branches || fileConfig.branches || ['main'],
    semverUpdateType: options.semverUpdateType || fileConfig.semverUpdateType || 'minor',
    allowOverrides: options.allowOverrides ?? fileConfig.allowOverrides ?? true,
  };
}
