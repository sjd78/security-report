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
  // Match patterns like "in package-name", "kin-openapi:", "package: package-name"
  const matchColon = text.match(/(?:CVE-\d{4}-\d+\s+[^:]+:\s*)([@a-zA-Z0-9._/-]+):/i);
  if (matchColon && matchColon[1]) {
    return matchColon[1].trim();
  }

  const matchIn = text.match(/(?:in|package|dependency)\s+[`"']?([@a-zA-Z0-9._/-]+)[`"']?/i);
  if (matchIn && matchIn[1] && !matchIn[1].startsWith('CVE-') && !matchIn[1].startsWith('GHSA-')) {
    return matchIn[1].trim();
  }

  return null;
}

export function extractVersionTagsFromText(text) {
  if (!text) return [];
  const tags = new Set();
  const matches = text.matchAll(/\[(?:mta-)?([0-9]+(?:\.[0-9]+)*)\]/gi);
  for (const m of matches) {
    if (m[1]) {
      tags.add(m[1]);
      tags.add(`mta-${m[1]}`);
      tags.add(`MTA ${m[1]}`);
    }
  }
  return Array.from(tags);
}

export function flattenAdfText(doc) {
  if (!doc) return '';
  if (typeof doc === 'string') return doc;
  if (typeof doc !== 'object') return String(doc);

  const texts = [];
  function recurse(node) {
    if (!node) return;
    if (typeof node.text === 'string') {
      texts.push(node.text);
    }
    if (Array.isArray(node.content)) {
      for (const child of node.content) {
        recurse(child);
      }
    }
  }
  recurse(doc);
  return texts.join(' ');
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

  const jql = customJql || `project = "${project || 'MTA'}" AND (summary ~ "CVE*" OR text ~ "CVE*" OR labels in (Security, SecurityTracking))`;
  const cleanBase = baseUrl.replace(/\/+$/, '');
  const maxResults = options.maxResults || 50;

  const fields = 'summary,description,status,labels,created,updated,versions,fixVersions,components';

  // Try 1: Modern Jira Cloud /rest/api/3/search/jql
  const jqlUrl = `${cleanBase}/rest/api/3/search/jql?jql=${encodeURIComponent(jql)}&maxResults=${maxResults}&fields=${fields}`;

  try {
    const res = await fetch(jqlUrl, {
      method: 'GET',
      headers: {
        Authorization: authHeader,
        Accept: 'application/json',
      },
    });

    if (res.ok) {
      const data = await res.json();
      return parseJiraIssues(data, cleanBase);
    }

    // Fallback 2: Legacy POST /rest/api/3/search
    const searchUrl = `${cleanBase}/rest/api/3/search`;
    const postRes = await fetch(searchUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: authHeader,
        Accept: 'application/json',
      },
      body: JSON.stringify({
        jql,
        fields: ['summary', 'description', 'status', 'created', 'updated', 'labels', 'versions', 'fixVersions'],
        maxResults,
      }),
    });

    if (postRes.ok) {
      return parseJiraIssues(await postRes.json(), cleanBase);
    }

    console.warn(`[Jira] Jira search returned HTTP ${res.status}: ${res.statusText}`);
    return [];
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
    const descText = flattenAdfText(issue.fields?.description);
    const combinedText = `${summary}\n${descText}`;
    const labels = issue.fields?.labels || [];

    // Look for CVE in labels first, then text
    let cve = null;
    for (const label of labels) {
      const found = extractCveFromText(label);
      if (found) {
        cve = found;
        break;
      }
    }
    if (!cve) {
      cve = extractCveFromText(combinedText);
    }

    const packageName = extractPackageNameFromText(summary) || extractPackageNameFromText(descText);

    // Extract affectsVersions and fixVersions
    const versionsSet = new Set();
    if (Array.isArray(issue.fields?.versions)) {
      for (const v of issue.fields.versions) {
        if (v.name) {
          versionsSet.add(v.name);
          const simple = v.name.replace(/^MTA\s*/i, '');
          versionsSet.add(simple);
        }
      }
    }
    if (Array.isArray(issue.fields?.fixVersions)) {
      for (const v of issue.fields.fixVersions) {
        if (v.name) versionsSet.add(v.name);
      }
    }

    // Also extract version tags from summary e.g. [mta-8.2]
    const summaryTags = extractVersionTagsFromText(summary);
    for (const st of summaryTags) {
      versionsSet.add(st);
    }

    tickets.push({
      ticketKey: key,
      summary,
      status: issue.fields?.status?.name || 'Open',
      url: `${baseUrl}/browse/${key}`,
      cve,
      packageName,
      labels,
      affectsVersions: Array.from(versionsSet),
    });
  }

  return tickets;
}
