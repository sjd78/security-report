import semver from 'semver';
import { lookupPackageInstalledInfo } from './dependency-graph.js';
import { buildRemediationSuggestion } from '../collectors/npm-audit.js';

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

export function compareSeverities(a, b) {
  const rank = { critical: 4, high: 3, moderate: 2, low: 1, info: 0 };
  return (rank[b?.toLowerCase()] || 0) - (rank[a?.toLowerCase()] || 0);
}

export function pickHighestSafeVersion(verA, verB) {
  if (!verA) return verB || null;
  if (!verB) return verA || null;
  const cleanA = semver.clean(String(verA).replace(/^[~^]/, ''));
  const cleanB = semver.clean(String(verB).replace(/^[~^]/, ''));
  if (cleanA && cleanB && semver.valid(cleanA) && semver.valid(cleanB)) {
    return semver.gt(cleanB, cleanA) ? verB : verA;
  }
  return verA || verB;
}

export function calculateOptimalSafeVersion(installedVersion, advisories = []) {
  const candidateVersions = [];

  for (const adv of advisories) {
    if (adv.targetSafeVersion) {
      candidateVersions.push(adv.targetSafeVersion);
    }
  }

  if (candidateVersions.length === 0) return null;

  let highest = candidateVersions[0];
  for (const candidate of candidateVersions) {
    highest = pickHighestSafeVersion(highest, candidate);
  }

  return highest;
}

export function matchJiraTicket(vuln, jiraTickets, branchName = null, branchMap = {}) {
  if (!jiraTickets || jiraTickets.length === 0) return null;

  const targetVersions = branchName && branchMap[branchName]
    ? (Array.isArray(branchMap[branchName]) ? branchMap[branchName] : [branchMap[branchName]])
    : [];

  for (const ticket of jiraTickets) {
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

export function consolidateVulnerabilitiesByPackage(rawVulnerabilities = []) {
  const packageMap = new Map();

  for (const v of rawVulnerabilities) {
    const pkgKey = (v.packageName || 'unknown').toLowerCase();

    if (!packageMap.has(pkgKey)) {
      const cves = v.cve ? [v.cve] : [];
      if (Array.isArray(v.cves)) {
        for (const c of v.cves) {
          if (!cves.includes(c)) cves.push(c);
        }
      }

      packageMap.set(pkgKey, {
        packageName: v.packageName,
        severity: v.severity || 'moderate',
        isDirect: Boolean(v.isDirect),
        isIndirect: Boolean(v.isIndirect),
        dependencyType: v.dependencyType || (v.isDirect ? 'Direct' : 'Indirect (Transitive)'),
        currentVersion: v.currentVersion || 'unknown',
        targetSafeVersion: v.targetSafeVersion || null,
        vulnerableVersionRange: v.vulnerableVersionRange || null,
        id: v.id,
        cve: v.cve || cves[0] || null,
        cves,
        title: v.title || `${v.packageName} vulnerability`,
        url: v.url || null,
        advisories: [
          {
            id: v.id,
            cve: v.cve || null,
            title: v.title,
            severity: v.severity,
            url: v.url,
            vulnerableVersionRange: v.vulnerableVersionRange,
            targetSafeVersion: v.targetSafeVersion,
            sources: v.sources,
          },
        ],
        dependencyPaths: [...(v.dependencyPaths || [])],
        directRoots: [...(v.directRoots || [])],
        sources: {
          jiraTickets: v.sources?.jira ? [v.sources.jira] : [],
          dependabotAlerts: v.sources?.dependabot ? [v.sources.dependabot] : [],
          jira: v.sources?.jira || null,
          dependabot: v.sources?.dependabot || null,
          npmAudit: v.sources?.npmAudit || null,
        },
        remediation: v.remediation ? { ...v.remediation } : null,
      });
    } else {
      const existing = packageMap.get(pkgKey);

      // 1. Upgrade severity to highest
      if (compareSeverities(existing.severity, v.severity) > 0) {
        existing.severity = v.severity;
      }

      // 2. Mark isDirect and isIndirect
      if (v.isDirect) existing.isDirect = true;
      if (v.isIndirect) existing.isIndirect = true;

      if (existing.isDirect && existing.isIndirect) {
        existing.dependencyType = 'Direct & Indirect';
      } else if (existing.isDirect) {
        existing.dependencyType = 'Direct';
      } else if (existing.isIndirect) {
        existing.dependencyType = 'Indirect (Transitive)';
      }

      // 3. Update current version if existing was placeholder
      if (existing.currentVersion === 'downstream-tracker' || existing.currentVersion === 'unknown') {
        if (v.currentVersion && v.currentVersion !== 'downstream-tracker' && v.currentVersion !== 'unknown') {
          existing.currentVersion = v.currentVersion;
        }
      }

      // 4. Collect unique CVEs
      if (v.cve && !existing.cves.includes(v.cve)) {
        existing.cves.push(v.cve);
        if (!existing.cve) existing.cve = v.cve;
      }
      if (Array.isArray(v.cves)) {
        for (const c of v.cves) {
          if (!existing.cves.includes(c)) existing.cves.push(c);
        }
      }

      // 5. Add advisory entry
      existing.advisories.push({
        id: v.id,
        cve: v.cve || null,
        title: v.title,
        severity: v.severity,
        url: v.url,
        vulnerableVersionRange: v.vulnerableVersionRange,
        targetSafeVersion: v.targetSafeVersion,
        sources: v.sources,
      });

      // 6. Merge dependency paths
      for (const p of v.dependencyPaths || []) {
        if (!existing.dependencyPaths.includes(p)) {
          existing.dependencyPaths.push(p);
        }
      }

      // 7. Merge direct roots
      for (const r of v.directRoots || []) {
        if (!existing.directRoots.some((dr) => dr.name === r.name)) {
          existing.directRoots.push(r);
        }
      }

      // 8. Merge Jira tickets
      if (v.sources?.jira) {
        if (!existing.sources.jiraTickets.some((t) => t.ticketKey === v.sources.jira.ticketKey)) {
          existing.sources.jiraTickets.push(v.sources.jira);
        }
        if (!existing.sources.jira) existing.sources.jira = v.sources.jira;
      }

      // 9. Merge Dependabot alerts
      if (v.sources?.dependabot) {
        if (!existing.sources.dependabotAlerts.some((a) => a.alertNumber === v.sources.dependabot.alertNumber)) {
          existing.sources.dependabotAlerts.push(v.sources.dependabot);
        }
        if (!existing.sources.dependabot) existing.sources.dependabot = v.sources.dependabot;
      }

      // 10. Merge remediation plan
      if (v.remediation) {
        if (!existing.remediation) {
          existing.remediation = { ...v.remediation };
        } else if (existing.remediation.strategy === 'jira-tracker' && v.remediation.strategy !== 'jira-tracker') {
          existing.remediation = { ...v.remediation };
        }
      }
    }
  }

  // Optimize target safe versions across all advisories for each package
  for (const pkg of packageMap.values()) {
    const optimalSafeVersion = calculateOptimalSafeVersion(pkg.currentVersion, pkg.advisories);
    if (optimalSafeVersion) {
      pkg.targetSafeVersion = optimalSafeVersion;
      if (pkg.remediation) {
        pkg.remediation.targetVersion = optimalSafeVersion;

        // If package is Direct & Indirect, update strategy
        if (pkg.dependencyType === 'Direct & Indirect' || (pkg.isDirect && pkg.isIndirect)) {
          pkg.remediation.strategy = 'bump-direct-and-lockfile';
          pkg.remediation.note = 'Package is both a direct dependency and required transitively. Resolution updates package.json semver and synchronizes lockfile for all instances.';
        }

        for (const chg of pkg.remediation.packageJsonChanges || []) {
          if (chg.package === pkg.packageName) {
            const prefix = chg.from?.startsWith('~') ? '~' : chg.from?.startsWith('^') ? '^' : '';
            chg.to = `${prefix}${optimalSafeVersion}`;
          }
        }
        let targetRange = optimalSafeVersion;
        const matchingChange = (pkg.remediation.packageJsonChanges || []).find((c) => c.package === pkg.packageName);
        if (matchingChange && matchingChange.to) {
          targetRange = matchingChange.to;
        }

        if (pkg.remediation.lockfileActions) {
          pkg.remediation.lockfileActions = pkg.remediation.lockfileActions.map((act) =>
            act.replace(new RegExp(`${pkg.packageName}@[^\\s]+`), `${pkg.packageName}@${targetRange}`)
          );
        }
      }
    }
  }

  const consolidated = Array.from(packageMap.values());
  consolidated.sort((a, b) => compareSeverities(b.severity, a.severity));
  return consolidated;
}

export function blendVulnerabilitySources(
  branchReports = [],
  { jiraTickets = [], dependabotAlerts = [], branchMap = {} } = {}
) {
  const enrichedBranchReports = [];

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

    const rawVulns = (branchReport.vulnerabilities || []).map((v) => {
      const copy = { ...v, sources: { ...(v.sources || {}) } };

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
        if (!copy.targetSafeVersion && matchedJira.targetSafeVersion) {
          copy.targetSafeVersion = matchedJira.targetSafeVersion;
        }
      }

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

    // Unmatched branch Jira tickets: assess actual installed version & dependency type from branch repo lockfile
    for (const ticket of branchJiraTickets) {
      if (!matchedJiraKeys.has(ticket.ticketKey)) {
        const pkgInfo = lookupPackageInstalledInfo(
          ticket.packageName,
          branchReport.pkgJson,
          branchReport.pkgLock,
          branchReport.npmLsData
        );

        const currentVersion = pkgInfo.currentVersion !== 'unknown'
          ? pkgInfo.currentVersion
          : 'downstream-tracker';

        const isDirect = pkgInfo.isDirect;
        const isIndirect = pkgInfo.isIndirect || (!isDirect && currentVersion !== 'unknown');
        const dependencyType = pkgInfo.dependencyType !== 'Unknown'
          ? pkgInfo.dependencyType
          : (isDirect ? 'Direct' : 'Indirect (Transitive)');

        const targetSafe = ticket.targetSafeVersion || null;

        const dummyVuln = {
          packageName: ticket.packageName,
          isDirect,
          isIndirect,
          dependencyType,
          currentVersion,
          targetSafeVersion: targetSafe,
        };

        const remediation = buildRemediationSuggestion(
          dummyVuln,
          pkgInfo.directRoots,
          branchReport.pkgJson,
          pkgInfo.chains
        );

        rawVulns.push({
          id: ticket.ghsaId || ticket.ticketKey,
          cve: ticket.cve,
          packageName: ticket.packageName || ticket.summary,
          severity: 'high',
          title: ticket.summary,
          url: ticket.advisoryUrl || ticket.url,
          isDirect,
          isIndirect,
          dependencyType,
          vulnerableVersionRange: ticket.vulnerableVersionRange || null,
          currentVersion,
          targetSafeVersion: targetSafe,
          dependencyPaths: pkgInfo.dependencyPaths.length > 0 ? pkgInfo.dependencyPaths : [ticket.packageName || ticket.summary],
          directRoots: pkgInfo.directRoots,
          sources: {
            jira: {
              ticketKey: ticket.ticketKey,
              url: ticket.url,
              summary: ticket.summary,
              status: ticket.status,
              affectsVersions: ticket.affectsVersions || [],
            },
          },
          remediation,
        });
      }
    }

    // Unmatched branch Dependabot alerts
    for (const alert of branchDependabotAlerts) {
      if (!matchedDependabotNumbers.has(alert.alertNumber)) {
        const pkgInfo = lookupPackageInstalledInfo(
          alert.packageName,
          branchReport.pkgJson,
          branchReport.pkgLock,
          branchReport.npmLsData
        );

        const currentVersion = pkgInfo.currentVersion !== 'unknown'
          ? pkgInfo.currentVersion
          : 'dependabot-alert';

        const isDirect = pkgInfo.isDirect;
        const isIndirect = pkgInfo.isIndirect || (!isDirect && currentVersion !== 'unknown');
        const dependencyType = pkgInfo.dependencyType !== 'Unknown'
          ? pkgInfo.dependencyType
          : (isDirect ? 'Direct' : 'Indirect (Transitive)');

        const dummyVuln = {
          packageName: alert.packageName,
          isDirect,
          isIndirect,
          dependencyType,
          currentVersion,
          targetSafeVersion: alert.targetSafeVersion,
        };

        const remediation = buildRemediationSuggestion(
          dummyVuln,
          pkgInfo.directRoots,
          branchReport.pkgJson,
          pkgInfo.chains
        );

        rawVulns.push({
          id: alert.ghsaId || `DEP-${alert.alertNumber}`,
          cve: alert.cve,
          packageName: alert.packageName,
          severity: alert.severity || 'moderate',
          title: alert.summary,
          url: alert.url,
          isDirect,
          isIndirect,
          dependencyType,
          vulnerableVersionRange: alert.vulnerableVersionRange,
          currentVersion,
          targetSafeVersion: alert.targetSafeVersion,
          dependencyPaths: pkgInfo.dependencyPaths.length > 0 ? pkgInfo.dependencyPaths : [alert.packageName],
          directRoots: pkgInfo.directRoots,
          sources: {
            dependabot: {
              alertNumber: alert.alertNumber,
              url: alert.url,
              ghsaId: alert.ghsaId,
              severity: alert.severity,
            },
          },
          remediation,
        });
      }
    }

    // Consolidate packages to a single entry per package
    const consolidatedPackages = consolidateVulnerabilitiesByPackage(rawVulns);

    const summary = {
      critical: consolidatedPackages.filter((v) => v.severity === 'critical').length,
      high: consolidatedPackages.filter((v) => v.severity === 'high').length,
      moderate: consolidatedPackages.filter((v) => v.severity === 'moderate').length,
      low: consolidatedPackages.filter((v) => v.severity === 'low').length,
      total: consolidatedPackages.length,
    };

    enrichedBranchReports.push({
      ...branchReport,
      summary,
      vulnerabilities: consolidatedPackages,
    });
  }

  return enrichedBranchReports;
}
