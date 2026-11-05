const titleTokens = new Set(['targetBranch', 'targetPackages', 'summary']);

export function renderPrTitle(template, { targetBranch, targetPackages, summary } = {}) {
  if (typeof template !== 'string') throw new Error('Pull request title template must be a string.');
  const values = { targetBranch, targetPackages: Array.isArray(targetPackages) ? targetPackages.join(', ') : targetPackages, summary };
  const rendered = template.replace(/\{([^{}]*)\}/g, (_, token) => {
    if (!titleTokens.has(token)) throw new Error('Unknown pull request title template token.');
    if (typeof values[token] !== 'string') throw new Error(`Missing pull request title value: ${token}.`);
    return values[token];
  });
  if (/[{}]/.test(template.replace(/\{([^{}]*)\}/g, ''))) throw new Error('Invalid pull request title template token.');
  return validateTitle(rendered);
}

function validateTitle(title) {
  if (typeof title !== 'string' || !title.trim() || /[\r\n\u2028\u2029\x00-\x1f\x7f]/.test(title)) {
    throw new Error('Pull request title must be non-empty and single-line.');
  }
  return title.trim();
}

const list = (value) => value === null || value === undefined ? [] : Array.isArray(value) ? value : [value];
const oneLine = (value) => String(value ?? '').replace(/\s+/g, ' ').trim();
const text = (value) => oneLine(value).replace(/[\\`*_\[\]<>]/g, '\\$&');
const code = (value) => `\`${oneLine(value).replace(/`/g, '&#96;')}\``;

function httpUrl(value) {
  if (typeof value !== 'string') return null;
  try {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password ? url : null;
  } catch {
    return null;
  }
}

function findingReferences(finding) {
  const links = new Map();
  const identifiers = new Set();
  const addLink = (value, label) => {
    const url = httpUrl(value);
    if (!url) return;
    const labels = links.get(url.href) || new Set();
    labels.add(label);
    links.set(url.href, labels);
  };
  const visit = (value, label = 'Advisory') => {
    if (Array.isArray(value)) {
      for (const child of value) visit(child, label);
    } else if (value && typeof value === 'object') {
      const kind = oneLine(list(value.source || value.type).join(' '));
      const jira = /jira/i.test(kind) || value.ticketKey !== undefined;
      const dependabot = /dependabot/i.test(kind) || value.alertNumber !== undefined;
      if (jira) label = 'Jira';
      else if (dependabot) label = 'Dependabot';
      else if (/npm.?audit/i.test(kind)) label = 'npm audit';
      const keys = list(value.ticketKey ?? (jira ? value.id : undefined)).map(oneLine).filter(Boolean);
      const alerts = list(value.alertNumber ?? (dependabot ? value.id : undefined)).map(oneLine).filter(Boolean);
      if (label === 'Jira' && keys.length) label += ` ${keys.join(', ')}`;
      if (label === 'Dependabot' && alerts.length) label += ` #${alerts.join(', #')}`;
      for (const [key, child] of Object.entries(value)) {
        const childLabel = /jira/i.test(key) ? 'Jira' : /dependabot/i.test(key) ? 'Dependabot' : /npm.?audit/i.test(key) ? 'npm audit' : label;
        visit(child, childLabel);
      }
    } else if (typeof value === 'string') {
      for (const id of value.match(/\b(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b/gi) || []) identifiers.add(id.toUpperCase().startsWith('CVE-') ? id.toUpperCase() : id.toLowerCase().replace(/^ghsa-/, 'GHSA-'));
      addLink(value, label);
    }
  };
  visit(finding.id);
  visit(finding.cves);
  addLink(finding.url, 'Advisory');
  visit(finding.references);
  for (const id of identifiers) addLink(id.startsWith('CVE-') ? `https://nvd.nist.gov/vuln/detail/${id}` : `https://github.com/advisories/${id}`, id);
  return [...links].map(([url, labels]) => `[${text([...labels].join(' / '))}](${url.replace(/[()<>]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`)})`);
}

function appendFindings(lines, findings, indent = '') {
  for (const finding of list(findings)) {
    if (!finding || typeof finding !== 'object') continue;
    const id = finding.id ? ` (${code(finding.id)})` : '';
    lines.push(`${indent}- **${text(finding.severity || 'unknown').toUpperCase()}**: ${text(finding.title || 'Security finding')}${id}`);
    for (const constraint of list(finding.constraints)) {
      if (!constraint || typeof constraint !== 'object') continue;
      if (constraint.vulnerableRange) lines.push(`${indent}  - Affected range: ${code(constraint.vulnerableRange)}.`);
      if (constraint.firstPatchedVersion) lines.push(`${indent}  - Advisory patch floor: ${code(constraint.firstPatchedVersion)}.`);
    }
    const references = findingReferences(finding);
    if (references.length) lines.push(`${indent}  - References: ${references.join(', ')}.`);
    if (list(finding.cves).length) lines.push(`${indent}  - CVEs: ${list(finding.cves).map(code).join(', ')}.`);
  }
}

function appendResolutions(lines, pkg, indent = '') {
  const resolutions = list(pkg.resolutions).filter((resolution) => resolution && typeof resolution === 'object');
  if (!resolutions.length) {
    lines.push(`${indent}- No installed-version resolution details were recorded.`);
    return;
  }
  lines.push(`${indent}- Per-installed-version resolutions:`);
  for (const resolution of resolutions) {
    const installed = code(resolution.installedVersion || 'unknown');
    const line = resolution.line ? ` (${code(`${resolution.line}.x`)})` : '';
    const target = resolution.targetVersion ? code(resolution.targetVersion) : 'no safe target recorded';
    const outcome = resolution.status === 'ready'
      ? `→ ${target} via ${code(resolution.strategy || 'unknown strategy')}`
      : resolution.status === 'resolved' ? 'already safe; no update planned'
        : `${text(resolution.status || 'unresolved')}${resolution.targetVersion ? `; candidate target ${target}` : ''}`;
    lines.push(`${indent}  - ${installed}${line}: ${outcome}.`);
    for (const reason of list(resolution.reasons)) lines.push(`${indent}    - ${text(reason)}`);
    for (const instance of list(resolution.instances)) {
      if (!instance || typeof instance !== 'object') continue;
      lines.push(`${indent}    - Installed at ${code(instance.location || 'location not recorded')}.`);
      for (const origin of list(instance.origins)) {
        if (!origin || typeof origin !== 'object') continue;
        const source = `${origin.workspace ? `${origin.workspace} (` : ''}${origin.packageJsonPath || 'package.json'}${origin.workspace ? ')' : ''} / ${origin.section || 'dependency'}`;
        const chain = list(origin.chain).map((link) => link?.name && link?.version ? `${link.name}@${link.version}` : null).filter(Boolean).join(' → ');
        lines.push(`${indent}      - Origin: ${code(source)}${chain ? `: ${code(chain)}` : ''}.`);
      }
    }
  }
}

function actionDescription(action) {
  if (action.type === 'update-dependency') return `Update ${code(action.package)} in ${code(action.file)} / ${code(action.section)}: ${code(action.expectedRange)} → ${code(action.targetRange)}.`;
  if (action.type === 'set-override') return `Set override in ${code(action.file)} at ${code(['overrides', ...list(action.scope), action.package].join(' / '))}: ${action.expectedValue === null ? 'absent' : code(action.expectedValue)} → ${code(action.targetVersion)}.`;
  if (action.type === 'update-lockfile') return `Re-resolve ${code(action.package)} in ${code('package-lock.json')} using npm's dependency resolver.`;
  throw new Error('Unsupported saved-plan action in pull request body.');
}

export function generatePullRequestBody(branchPlan, executionResult = {}) {
  if (!branchPlan || typeof branchPlan !== 'object' || typeof branchPlan.branch !== 'string') throw new Error('A branch plan is required for the pull request body.');
  const verified = executionResult.verified === true && executionResult.dryRun !== true;
  const packages = list(branchPlan.packages);
  const ready = packages.filter((pkg) => pkg.status === 'ready');
  const lines = [
    `## Security remediation for ${code(branchPlan.branch)}`,
    '',
    text(branchPlan.summary || 'Apply the saved security remediation plan.'),
    '',
    `- Target branch: ${code(branchPlan.branch)}.`,
    `- Scanned base commit: ${branchPlan.baseCommit ? code(branchPlan.baseCommit) : 'not recorded'}.`,
    '- Planned targets below describe intent; only the verification section reports observed outcomes.',
    '',
    '## Planned packages and security motivation',
    '',
  ];
  if (!ready.length) lines.push('No packages have executable remediation actions.', '');
  for (const pkg of ready) {
    lines.push(`### ${code(pkg.packageName)}`, '');
    const before = list(pkg.installedVersions).filter(Boolean);
    lines.push(`- Scanned installed versions: ${before.length ? before.map(code).join(', ') : 'not recorded'}.`);
    appendResolutions(lines, pkg);
    appendFindings(lines, pkg.findings);
    lines.push('');
  }
  lines.push('## Saved plan actions', '');
  const actions = list(branchPlan.actions);
  if (!actions.length) lines.push('No file changes are planned.');
  for (const action of actions) {
    lines.push(`- ${actionDescription(action)}`);
    if (action.packageNames?.length) lines.push(`  - Motivating packages: ${action.packageNames.map(code).join(', ')}.`);
    if (action.findingIds?.length) lines.push(`  - Motivating findings: ${action.findingIds.map(code).join(', ')}.`);
    if (action.resolutionIds?.length) lines.push(`  - Covered installed resolutions: ${action.resolutionIds.map(code).join(', ')}.`);
  }
  lines.push('', '## Execution and verification', '');
  if (executionResult.dryRun === true) {
    lines.push('**Dry run — unverified.** No dependency changes were applied and no post-remediation audit was run.');
  } else if (!verified) {
    lines.push('**Unverified.** No verified installed-package outcome or clean-audit claim is available.');
  } else {
    const resolved = list(executionResult.resolved);
    lines.push(`The executor verified ${resolved.length} planned package${resolved.length === 1 ? '' : 's'} against installed instances and the post-remediation npm audit.`);
    for (const pkg of resolved) {
      const installed = list(pkg.installedVersions).filter(Boolean);
      lines.push(`- Verified ${code(pkg.packageName)}; observed installed versions: ${installed.length ? installed.map(code).join(', ') : 'not supplied'}.`);
    }
    const total = executionResult.postAuditSummary?.total;
    const remaining = Array.isArray(executionResult.remaining) ? executionResult.remaining : null;
    if (Number.isSafeInteger(total) && total >= 0 && (total !== 0 || (remaining?.length === 0 && executionResult.isClean === true))) {
      lines.push('', `Post-remediation npm audit reported **${total}** remaining vulnerability finding${total === 1 ? '' : 's'}. This does not close or resolve external Jira or Dependabot records.`);
      const counts = ['critical', 'high', 'moderate', 'low', 'info'].filter((severity) => Number.isSafeInteger(executionResult.postAuditSummary[severity]) && executionResult.postAuditSummary[severity] >= 0);
      if (counts.length) lines.push(`Audit severity counts: ${counts.map((severity) => `${severity}: ${executionResult.postAuditSummary[severity]}`).join(', ')}.`);
    } else {
      lines.push('', 'A complete, consistent npm audit summary was not supplied; no repository-wide clean-audit claim is made.');
    }
    if (remaining?.length) {
      lines.push('', '### Remaining npm audit findings', '');
      for (const finding of remaining) {
        if (finding.packageName) lines.push(`- Package: ${code(finding.packageName)}.`);
        appendFindings(lines, [finding]);
      }
    }
    if (executionResult.appliedChanges?.length) {
      lines.push('', '### Observed manifest changes', '');
      for (const change of executionResult.appliedChanges) {
        lines.push(`- ${code(change.package)} in ${code(change.file || 'package.json')} / ${code(change.section || 'dependencies')}: ${change.from === null || change.from === undefined ? 'absent' : code(change.from)} → ${code(change.to)}.`);
      }
    }
    if (executionResult.lockfileUpdates?.length) lines.push('', `Reported lockfile re-resolutions: ${executionResult.lockfileUpdates.map(code).join(', ')}.`);
    if (executionResult.touchedFiles?.length) lines.push('', `Changed files reported by the executor: ${executionResult.touchedFiles.map(code).join(', ')}.`);
  }
  lines.push('', '## Packages without a planned fix / unresolved disclosures', '');
  const disclosed = new Map();
  for (const pkg of [...packages.filter((pkg) => pkg.status !== 'ready'), ...list(executionResult.unresolved)]) {
    const key = `${pkg.packageName}:${pkg.status}`;
    const previous = disclosed.get(key);
    disclosed.set(key, previous ? {
      ...previous,
      reasons: [...new Set([...list(previous.reasons), ...list(pkg.reasons)])],
      findings: [...new Map([...list(previous.findings), ...list(pkg.findings)].map((finding) => [JSON.stringify(finding), finding])).values()],
    } : pkg);
  }
  if (!disclosed.size) lines.push('The saved plan and execution result contain no additional unresolved package disclosures. This is not a claim that the repository is vulnerability-free.');
  for (const pkg of disclosed.values()) {
    lines.push(`### ${code(pkg.packageName)} — ${text(pkg.status || 'unresolved')}`, '');
    for (const reason of list(pkg.reasons)) lines.push(`- ${text(reason)}`);
    if (pkg.status === 'resolved') lines.push('- Already marked resolved in the saved scan; no new fix is claimed here.');
    if (pkg.status === 'not-installed') lines.push('- Not installed in the saved scan; no remediation was planned.');
    if (list(pkg.resolutions).length) appendResolutions(lines, pkg);
    appendFindings(lines, pkg.findings);
    lines.push('');
  }
  return `${lines.join('\n').trim()}\n`;
}

function validateBranch(value) {
  return typeof value === 'string' && value.length > 0 && !/[\s\x00-\x1f\x7f~^:?*\[\\]/.test(value) && !value.includes('..') && !value.includes('@{') && value !== '@' && !value.startsWith('/') && !value.endsWith('/') && !value.endsWith('.') && value.split('/').every((part) => part && !part.startsWith('.') && !part.endsWith('.lock'));
}

function matchesIdentity(value, expected) {
  return typeof value === 'string' && value.toLowerCase() === expected.toLowerCase();
}

function validRepositoryIdentity(value, owner, name) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && (value.name !== undefined || value.full_name !== undefined)
    && (value.name === undefined || matchesIdentity(value.name, name))
    && (value.full_name === undefined || matchesIdentity(value.full_name, `${owner}/${name}`))
    && (value.owner === undefined || (value.owner && !Array.isArray(value.owner) && matchesIdentity(value.owner.login, owner)));
}

function validPullRequestSide(value, ref, owner, name) {
  return value === undefined || (value && typeof value === 'object' && !Array.isArray(value)
    && value.ref === ref
    && (value.label === undefined || (typeof value.label === 'string' && value.label.includes(':')
      && matchesIdentity(value.label.slice(0, value.label.indexOf(':')), owner)
      && value.label.slice(value.label.indexOf(':') + 1) === ref))
    && (value.user === undefined || (value.user && !Array.isArray(value.user) && matchesIdentity(value.user.login, owner)))
    && (value.repo === undefined || validRepositoryIdentity(value.repo, owner, name)));
}

function validPullRequest(value, { head, base, org, name, headOwner, headRepo }) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Number.isSafeInteger(value.number) && value.number > 0 && httpUrl(value.html_url)
    && (value.state === undefined || value.state === 'open')
    && validPullRequestSide(value.head, head, headOwner, headRepo)
    && validPullRequestSide(value.base, base, org, name);
}

export async function publishPullRequest({ org, name, headOwner = org, headRepo = name, head, base, title, body, githubToken, githubApiUrl = 'https://api.github.com' } = {}) {
  if (![org, headOwner].every((value) => typeof value === 'string' && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(value))
    || ![name, headRepo].every((value) => typeof value === 'string' && /^[a-z0-9_.-]+$/i.test(value) && !value.startsWith('-') && !['.', '..'].includes(value))) throw new Error('A valid GitHub repository owner and name are required.');
  const crossRepository = !matchesIdentity(headOwner, org) || !matchesIdentity(headRepo, name);
  if (!validateBranch(head) || !validateBranch(base) || (!crossRepository && head === base)) throw new Error('Distinct valid pull request head and base branches are required unless using different repositories.');
  const identity = { head, base, org, name, headOwner, headRepo };
  title = validateTitle(title);
  if (typeof body !== 'string' || !body.trim()) throw new Error('A non-empty pull request body is required.');
  if (typeof githubToken !== 'string' || !githubToken || /\s|[\x00-\x1f\x7f]/.test(githubToken)) throw new Error('A non-empty GitHub token is required to publish a pull request.');
  const api = httpUrl(githubApiUrl);
  if (!api || api.search || api.hash) throw new Error('A valid credential-free GitHub API base URL is required.');
  const endpoint = `${api.href.replace(/\/+$/, '')}/repos/${encodeURIComponent(org)}/${encodeURIComponent(name)}/pulls`;
  const headers = { Accept: 'application/vnd.github+json', Authorization: `Bearer ${githubToken}`, 'X-GitHub-Api-Version': '2022-11-28' };
  const request = async (url, method, payload, operation) => {
    let response;
    try {
      response = await fetch(url, { method, headers: payload ? { ...headers, 'Content-Type': 'application/json' } : headers, ...(payload ? { body: JSON.stringify(payload) } : {}), redirect: 'error' });
    } catch {
      throw new Error(`GitHub pull request ${operation} request failed.`);
    }
    if (!response.ok) {
      try { await response.body?.cancel(); } catch { /* Discard untrusted transport error details. */ }
      throw new Error(`GitHub pull request ${operation} failed (HTTP ${response.status}).`);
    }
    try {
      return await response.json();
    } catch {
      throw new Error(`GitHub pull request ${operation} returned malformed JSON.`);
    }
  };
  const query = new URL(endpoint);
  query.search = new URLSearchParams({ state: 'open', head: `${headOwner}:${head}`, base, per_page: '100' }).toString();
  const existing = await request(query, 'GET', null, 'lookup');
  if (!Array.isArray(existing) || existing.some((pr) => !validPullRequest(pr, identity))) throw new Error('GitHub pull request lookup returned a malformed response.');
  if (existing.length > 1) throw new Error('GitHub returned multiple matching open pull requests.');
  const current = existing[0];
  const created = !current;
  const creation = { head: crossRepository ? `${headOwner}:${head}` : head, ...(crossRepository ? { head_repo: headRepo } : {}), base, title, body };
  const result = await request(current ? `${endpoint}/${current.number}` : endpoint, current ? 'PATCH' : 'POST', current ? { title, body } : creation, current ? 'update' : 'creation');
  if (!validPullRequest(result, identity) || (current && result.number !== current.number)) throw new Error('GitHub pull request publishing returned a malformed response.');
  return { number: result.number, url: result.html_url, created };
}
