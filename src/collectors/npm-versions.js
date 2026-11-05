import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import semver from 'semver';

const execFileAsync = promisify(execFile);
const packageNamePattern = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;

export async function fetchPublishedVersions(worktreeDir, packageNames) {
  const results = new Map();
  const names = [...new Set(packageNames || [])];
  await Promise.all(names.map(async (packageName) => {
    if (typeof packageName !== 'string' || !packageNamePattern.test(packageName)) {
      results.set(packageName, { versions: null, error: 'Invalid npm package name; release catalog was not queried.' });
      return;
    }
    try {
      const { stdout } = await execFileAsync('npm', ['view', packageName, 'versions', '--json'], {
        cwd: worktreeDir,
        maxBuffer: 10 * 1024 * 1024,
      });
      const parsed = JSON.parse(stdout);
      const returned = typeof parsed === 'string' ? [parsed] : parsed;
      if (!Array.isArray(returned) || returned.some((version) => typeof version !== 'string')) {
        results.set(packageName, { versions: null, error: `npm view returned an invalid version catalog for ${packageName}.` });
        return;
      }
      const versions = [...new Set(returned.map((version) => semver.valid(version)).filter((version) => version && !semver.prerelease(version)))];
      versions.sort(semver.compare);
      results.set(packageName, { versions, error: null });
    } catch (error) {
      const code = Number.isInteger(error?.code) ? ` (exit code ${error.code})` : '';
      results.set(packageName, { versions: null, error: `npm view failed for ${packageName}${code}; registry release catalog is unavailable.` });
    }
  }));
  return results;
}
