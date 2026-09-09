import { extractCveFromText } from './npm-audit.js';

export function createJiraAuthHeader(config) {
  const { email, apiToken } = config.jira || {};
  if (!apiToken) return null;

  if (email) {
    const creds = Buffer.from(`${email}:${apiToken}`).toString('base64');
    return `Basic ${creds}`;
  }

  return `Bearer ${apiToken}`;
}

export function extractPackageNameFromText(text) {
  if (!text) return null;
  // Match patterns like "in package-name", "in `package-name`", "package: package-name"
  const matchIn = text.match(/(?:in|package|dependency)\s+[`"']?([@a-zA-Z0-9._/-]+)[`"']?/i);
  if (matchIn && matchIn[1] && !matchIn[1].startsWith('CVE-') && !matchIn[1].startsWith('GHSA-')) {
    return matchIn[1];
  }
  return null;
}

export async function fetchJiraCveTickets(config = {}, options = {}) {
  const { baseUrl, project, jql: customJql } = config.jira || {};
  if (!baseUrl) {
    return [];
  }

  const authHeader = createJiraAuthHeader(config);
  if (!authHeader) {
    console.warn('[Jira] Warning: Jira API token not configured. Skipping Jira ticket lookup.');
    return [];
  }

  const jql = customJql || `project = "${project || 'SEC'}" AND statusCategory != Done AND (summary ~ "CVE-*" OR description ~ "CVE-*")`;
  const cleanBase = baseUrl.replace(/\/+$/, '');
  const searchUrl = `${cleanBase}/rest/api/3/search`;

  try {
    const res = await fetch(searchUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: authHeader,
        Accept: 'application/json',
      },
      body: JSON.stringify({
        jql,
        fields: ['summary', 'description', 'status', 'created', 'updated', 'labels'],
        maxResults: options.maxResults || 100,
      }),
    });

    if (!res.ok) {
      // Try fallback to v2 search API
      const fallbackUrl = `${cleanBase}/rest/api/2/search`;
      const fallbackRes = await fetch(fallbackUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: authHeader,
          Accept: 'application/json',
        },
        body: JSON.stringify({
          jql,
          fields: ['summary', 'description', 'status', 'created', 'updated', 'labels'],
          maxResults: options.maxResults || 100,
        }),
      });

      if (!fallbackRes.ok) {
        console.warn(`[Jira] Jira search returned HTTP ${res.status}: ${res.statusText}`);
        return [];
      }

      return parseJiraIssues(await fallbackRes.json(), cleanBase);
    }

    return parseJiraIssues(await res.json(), cleanBase);
  } catch (err) {
    console.warn(`[Jira] Error fetching Jira CVE tickets: ${err.message}`);
    return [];
  }
}

export function parseJiraIssues(data, baseUrl) {
  const issues = data.issues || [];
  const tickets = [];

  for (const issue of issues) {
    const key = issue.key;
    const summary = issue.fields?.summary || '';
    const desc = typeof issue.fields?.description === 'string' ? issue.fields.description : JSON.stringify(issue.fields?.description || '');
    const combinedText = `${summary}\n${desc}`;

    const cve = extractCveFromText(combinedText);
    const packageName = extractPackageNameFromText(summary) || extractPackageNameFromText(desc);

    tickets.push({
      ticketKey: key,
      summary,
      status: issue.fields?.status?.name || 'Open',
      url: `${baseUrl}/browse/${key}`,
      cve,
      packageName,
      labels: issue.fields?.labels || [],
    });
  }

  return tickets;
}
