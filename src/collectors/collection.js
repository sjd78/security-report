// Collector records live once, under their package, rather than in parallel flat lists.
export function groupPackageFindings(findings = []) {
  const packages = new Map();
  for (const { packageName = null, ...finding } of findings) {
    if (!packages.has(packageName)) packages.set(packageName, { packageName, findings: [] });
    packages.get(packageName).findings.push(finding);
  }
  return [...packages.values()].sort((a, b) => String(a.packageName || '').localeCompare(String(b.packageName || '')));
}

export function getBranchFindings(collection, branch) {
  const group = collection?.branches?.find((entry) => entry.branch === branch);
  return (group?.packages || []).flatMap(({ packageName, findings }) =>
    findings.map((finding) => ({ ...finding, packageName })));
}
