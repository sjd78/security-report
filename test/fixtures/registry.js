import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';

const exec = promisify(execFile);
export const fixturePackage = 'security-report-fixture';
export const fixtureGhsa = 'GHSA-2345-6789-CFGH';

// Real npm uses this loopback registry; neither package resolution nor advisory enrichment uses the internet.
export async function startRegistry(directory) {
  fs.mkdirSync(directory, { recursive: true });
  const userConfig = path.join(directory, 'npmrc');
  fs.writeFileSync(userConfig, '');
  const env = {
    npm_config_userconfig: userConfig,
    npm_config_globalconfig: path.join(directory, 'global-npmrc'),
    npm_config_cache: path.join(directory, 'cache'),
    npm_config_fetch_retries: '0',
    npm_config_update_notifier: 'false',
    npm_config_ignore_scripts: 'true',
  };
  fs.writeFileSync(env.npm_config_globalconfig, '');
  const tarballs = new Map();
  for (const version of ['1.0.0', '1.0.1']) {
    const dir = path.join(directory, version);
    fs.mkdirSync(dir);
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: fixturePackage, version }));
    fs.writeFileSync(path.join(dir, 'index.js'), `module.exports = '${version}';\n`);
    const { stdout } = await exec('npm', ['pack', '--json', '--ignore-scripts'], {
      cwd: dir, env: { ...process.env, ...env },
    });
    const [packed] = JSON.parse(stdout);
    const bytes = fs.readFileSync(path.join(dir, packed.filename));
    tarballs.set(version, { bytes, integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}` });
  }
  let url;
  const requests = [];
  const state = { failAudit: false };
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const bytes = Buffer.concat(chunks);
    const body = bytes.length ? JSON.parse((req.headers['content-encoding'] === 'gzip' ? gunzipSync(bytes) : bytes).toString()) : null;
    requests.push({ method: req.method, path: req.url, body });
    res.setHeader('content-type', 'application/json');
    const send = (value, status = 200) => { res.writeHead(status); res.end(JSON.stringify(value)); };
    if (req.url === '/-/npm/v1/security/advisories/bulk' || req.url === '/-/npm/v1/security/audits/quick') {
      if (state.failAudit) return send({ error: 'Registry unavailable' }, 503);
      return send({ [fixturePackage]: [{ id: 1234, name: fixturePackage,
        url: `${url}/github/advisories/${fixtureGhsa}`, title: 'Fixture denial of service', severity: 'high',
        vulnerable_versions: '<1.0.1', cwe: ['CWE-400'], cvss: { score: 7.5, vectorString: null } }] });
    }
    if (req.url === `/${fixturePackage}`) {
      return send({ name: fixturePackage, 'dist-tags': { latest: '1.0.1' }, versions: Object.fromEntries(
        [...tarballs].map(([version, packed]) => [version, { name: fixturePackage, version,
          dist: { tarball: `${url}/${fixturePackage}/-/${version}.tgz`, integrity: packed.integrity } }]),
      ) });
    }
    const tarball = req.url.match(/\/-\/(1\.0\.[01])\.tgz$/);
    if (tarball) { res.setHeader('content-type', 'application/octet-stream'); return res.end(tarballs.get(tarball[1]).bytes); }
    if (req.url === `/github/advisories/${fixtureGhsa}`) {
      return send({ ghsa_id: fixtureGhsa, cve_id: 'CVE-2026-12345', severity: 'high',
        summary: 'Fixture denial of service', html_url: `https://github.com/advisories/${fixtureGhsa}`,
        vulnerabilities: [{ package: { name: fixturePackage, ecosystem: 'npm' }, vulnerable_version_range: '<1.0.1', first_patched_version: '1.0.1' }] });
    }
    return send({ message: 'Not found' }, 404);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  url = `http://127.0.0.1:${server.address().port}`;
  env.npm_config_registry = url;
  return {
    url, env, requests, state,
    packageLock() {
      return { name: 'fixture-app', version: '1.0.0', lockfileVersion: 3, requires: true, packages: {
        '': { name: 'fixture-app', version: '1.0.0', dependencies: { [fixturePackage]: '1.0.0' } },
        [`node_modules/${fixturePackage}`]: { version: '1.0.0', resolved: `${url}/${fixturePackage}/-/1.0.0.tgz`, integrity: tarballs.get('1.0.0').integrity },
      } };
    },
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
