export function isVersionCompatible(ticketVersions = [], targetVersions = []) {
  if (!targetVersions || targetVersions.length === 0) return true;
  if (!ticketVersions || ticketVersions.length === 0) return true;

  for (const tv of ticketVersions) {
    const cleanTv = String(tv).toLowerCase().replace(/^mta\s*|-/g, '').trim();

    for (const target of targetVersions) {
      const cleanTarget = String(target).toLowerCase().replace(/^mta\s*|-/g, '').replace(/\.x$/i, '').trim();

      if (cleanTv === cleanTarget || cleanTv.startsWith(cleanTarget) || cleanTarget.startsWith(cleanTv)) {
        return true;
      }
    }
  }

  return false;
}

export function matchJiraTicket(vuln, jiraTickets, branchName = null, branchMap = {}) {
  if (!jiraTickets || jiraTickets.length === 0) return null;

  const targetVersions = branchName && branchMap[branchName]
    ? (Array.isArray(branchMap[branchName]) ? branchMap[branchName] : [branchMap[branchName]])
    : [];

  for (const ticket of jiraTickets) {
    // Check version compatibility if branchMap is defined
    if (targetVersions.length > 0) {
      const compatible = isVersionCompatible(ticket.affectsVersions, targetVersions);
      if (!compatible) continue;
    }

    // Exact CVE match
    if (vuln.cve && ticket.cve && vuln.cve.toUpperCase() === ticket.cve.toUpperCase()) {
      return ticket;
    }

    // Advisory ID match
    if (vuln.id && (ticket.summary?.includes(vuln.id) || ticket.ticketKey?.includes(vuln.id))) {
      return ticket;
    }

    // Package name match
    if (ticket.packageName && vuln.packageName && ticket.packageName.toLowerCase() === vuln.packageName.toLowerCase()) {
      return ticket;
    }
  }

  return null;
}

export function matchDependabotAlert(vuln, dependabotAlerts) {
  if (!dependabotAlerts || dependabotAlerts.length === 0) return null;

  for (const alert of dependabotAlerts) {
    // GHSA match
    if (vuln.id && alert.ghsaId && vuln.id.toUpperCase() === alert.ghsaId.toUpperCase()) {
      return alert;
    }

    // CVE match
    if (vuln.cve && alert.cve && vuln.cve.toUpperCase() === alert.cve.toUpperCase()) {
      return alert;
    }

    // Package match
    if (vuln.packageName && alert.packageName && vuln.packageName.toLowerCase() === alert.packageName.toLowerCase()) {
      return alert;
    }
  }

  return null;
}

export function blendVulnerabilitySources(
  branchReports = [],
  { jiraTickets = [], dependabotAlerts = [], branchMap = {} } = {}
) {
  const enrichedBranchReports = [];

  // Extract branch-specific ticket and alert maps if available
  const jiraBranchMap = new Map();
  if (jiraTickets && typeof jiraTickets === 'object' && Array.isArray(jiraTickets.branches)) {
    for (const bg of jiraTickets.branches) {
      jiraBranchMap.set(bg.branch, bg.tickets || []);
    }
  }

  const dependabotBranchMap = new Map();
  if (dependabotAlerts && typeof dependabotAlerts === 'object' && Array.isArray(dependabotAlerts.branches)) {
    for (const bg of dependabotAlerts.branches) {
      dependabotBranchMap.set(bg.branch, bg.alerts || []);
    }
  }

  const allJiraList = Array.isArray(jiraTickets) ? jiraTickets : (jiraTickets?.allTickets || []);
  const allDependabotList = Array.isArray(dependabotAlerts) ? dependabotAlerts : (dependabotAlerts?.allAlerts || []);

  for (const branchReport of branchReports) {
    const branchName = branchReport.branch;

    const branchJiraTickets = jiraBranchMap.has(branchName)
      ? jiraBranchMap.get(branchName)
      : allJiraList;

    const branchDependabotAlerts = dependabotBranchMap.has(branchName)
      ? dependabotBranchMap.get(branchName)
      : allDependabotList;

    const matchedJiraKeys = new Set();
    const matchedDependabotNumbers = new Set();

    const vulnerabilities = (branchReport.vulnerabilities || []).map((v) => {
      const copy = { ...v, sources: { ...(v.sources || {}) } };

      // 1. Blend Jira with branch version awareness
      const matchedJira = matchJiraTicket(copy, branchJiraTickets, branchName, branchMap);
      if (matchedJira) {
        matchedJiraKeys.add(matchedJira.ticketKey);
        copy.sources.jira = {
          ticketKey: matchedJira.ticketKey,
          url: matchedJira.url,
          summary: matchedJira.summary,
          status: matchedJira.status,
          affectsVersions: matchedJira.affectsVersions || [],
        };
        if (!copy.cve && matchedJira.cve) {
          copy.cve = matchedJira.cve;
        }
      }

      // 2. Blend Dependabot
      const matchedDependabot = matchDependabotAlert(copy, branchDependabotAlerts);
      if (matchedDependabot) {
        matchedDependabotNumbers.add(matchedDependabot.alertNumber);
        copy.sources.dependabot = {
          alertNumber: matchedDependabot.alertNumber,
          url: matchedDependabot.url,
          ghsaId: matchedDependabot.ghsaId,
          severity: matchedDependabot.severity,
        };
        if (!copy.cve && matchedDependabot.cve) {
          copy.cve = matchedDependabot.cve;
        }
        if (!copy.targetSafeVersion && matchedDependabot.targetSafeVersion) {
          copy.targetSafeVersion = matchedDependabot.targetSafeVersion;
        }
      }

      return copy;
    });

    // Append any branch Jira tickets not matched to npm audit findings (e.g. when npmAudit is disabled or Jira has extra findings)
    for (const ticket of branchJiraTickets) {
      if (!matchedJiraKeys.has(ticket.ticketKey)) {
        vulnerabilities.push({
          id: ticket.ticketKey,
          cve: ticket.cve,
          packageName: ticket.packageName || ticket.summary,
          severity: 'high',
          title: ticket.summary,
          url: ticket.url,
          isDirect: false,
          vulnerableVersionRange: null,
          currentVersion: 'downstream-tracker',
          targetSafeVersion: null,
          dependencyPaths: [ticket.packageName || ticket.summary],
          directRoots: [],
          sources: {
            jira: {
              ticketKey: ticket.ticketKey,
              url: ticket.url,
              summary: ticket.summary,
              status: ticket.status,
              affectsVersions: ticket.affectsVersions || [],
            },
          },
          remediation: {
            strategy: 'jira-tracker',
            packageJsonChanges: [],
            lockfileActions: [],
            note: `Tracked in Jira issue ${ticket.ticketKey} (${ticket.status})`,
          },
        });
      }
    }

    // Append any branch Dependabot alerts not matched
    for (const alert of branchDependabotAlerts) {
      if (!matchedDependabotNumbers.has(alert.alertNumber)) {
        vulnerabilities.push({
          id: alert.ghsaId || `DEP-${alert.alertNumber}`,
          cve: alert.cve,
          packageName: alert.packageName,
          severity: alert.severity || 'moderate',
          title: alert.summary,
          url: alert.url,
          isDirect: false,
          vulnerableVersionRange: alert.vulnerableVersionRange,
          currentVersion: 'dependabot-alert',
          targetSafeVersion: alert.targetSafeVersion,
          dependencyPaths: [alert.packageName],
          directRoots: [],
          sources: {
            dependabot: {
              alertNumber: alert.alertNumber,
              url: alert.url,
              ghsaId: alert.ghsaId,
              severity: alert.severity,
            },
          },
          remediation: {
            strategy: 'lockfile-update',
            targetPackage: alert.packageName,
            targetVersion: alert.targetSafeVersion,
            packageJsonChanges: [],
            lockfileActions: alert.targetSafeVersion
              ? [`npm install ${alert.packageName}@${alert.targetSafeVersion} --package-lock-only`]
              : [],
          },
        });
      }
    }

    const summary = {
      critical: vulnerabilities.filter((v) => v.severity === 'critical').length,
      high: vulnerabilities.filter((v) => v.severity === 'high').length,
      moderate: vulnerabilities.filter((v) => v.severity === 'moderate').length,
      low: vulnerabilities.filter((v) => v.severity === 'low').length,
      total: vulnerabilities.length,
    };

    enrichedBranchReports.push({
      ...branchReport,
      summary,
      vulnerabilities,
    });
  }

  return enrichedBranchReports;
}
