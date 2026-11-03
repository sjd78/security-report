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
export async function startRegistry(directory, {
  packageNames = [fixturePackage], versions = ['1.0.0', '1.0.1'],
  dependenciesByPackage = {}, vulnerablePackages = packageNames,
} = {}) {
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
  for (const name of packageNames) {
    const releases = new Map();
    for (const version of versions) {
      const dir = path.join(directory, name.replaceAll('/', '_'), version);
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
        name, version, ...(dependenciesByPackage[name] ? { dependencies: dependenciesByPackage[name] } : {}),
      }));
      fs.writeFileSync(path.join(dir, 'index.js'), `module.exports = '${version}';\n`);
      const { stdout } = await exec('npm', ['pack', '--json', '--ignore-scripts'], {
        cwd: dir, env: { ...process.env, ...env },
      });
      const [packed] = JSON.parse(stdout);
      const bytes = fs.readFileSync(path.join(dir, packed.filename));
      releases.set(version, { bytes, integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}` });
    }
    tarballs.set(name, releases);
  }
  let url;
  const requests = [];
  const state = { failAudit: false, failPr: false, pullRequests: [] };
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
      return send(Object.fromEntries(vulnerablePackages.filter((name) => body?.[name]).map((name, index) => [name, [{
        id: 1234 + index, name, url: `${url}/github/advisories/${fixtureGhsa}`,
        title: 'Fixture denial of service', severity: 'high', vulnerable_versions: '<1.0.1',
        cwe: ['CWE-400'], cvss: { score: 7.5, vectorString: null },
      }]])));
    }
    const packageName = packageNames.find((name) => req.url === `/${name}`);
    if (packageName) {
      return send({ name: packageName, 'dist-tags': { latest: versions.at(-1) }, versions: Object.fromEntries(
        [...tarballs.get(packageName)].map(([version, packed]) => [version, { name: packageName, version,
          ...(dependenciesByPackage[packageName] ? { dependencies: dependenciesByPackage[packageName] } : {}),
          dist: { tarball: `${url}/${packageName}/-/${version}.tgz`, integrity: packed.integrity } }]),
      ) });
    }
    for (const name of packageNames) {
      const version = versions.find((release) => req.url === `/${name}/-/${release}.tgz`);
      if (version) { res.setHeader('content-type', 'application/octet-stream'); return res.end(tarballs.get(name).get(version).bytes); }
    }
    if (req.url === `/github/advisories/${fixtureGhsa}`) {
      return send({ ghsa_id: fixtureGhsa, cve_id: 'CVE-2026-12345', severity: 'high',
        summary: 'Fixture denial of service', html_url: `https://github.com/advisories/${fixtureGhsa}`,
        vulnerabilities: vulnerablePackages.map((name) => ({ package: { name, ecosystem: 'npm' }, vulnerable_version_range: '<1.0.1', first_patched_version: '1.0.1' })) });
    }
    const parsedUrl = new URL(req.url, url);
    const pullRoute = parsedUrl.pathname.match(/\/repos\/([^/]+)\/([^/]+)\/pulls$/);
    if (pullRoute) {
      if (state.failPr) return send({ message: 'Publishing denied' }, 403);
      if (req.method === 'GET') return send(state.pullRequests.filter((pr) =>
        `${pr.head.repo.owner.login}:${pr.head.ref}` === parsedUrl.searchParams.get('head')
        && pr.base.ref === parsedUrl.searchParams.get('base')
        && pr.base.repo.full_name === `${pullRoute[1]}/${pullRoute[2]}`));
      if (req.method === 'POST') {
        const [baseOwner, baseName] = pullRoute.slice(1);
        const separator = body.head.indexOf(':');
        const headOwner = separator === -1 ? baseOwner : body.head.slice(0, separator);
        const head = separator === -1 ? body.head : body.head.slice(separator + 1);
        const headName = body.head_repo || baseName;
        const pr = { number: state.pullRequests.length + 1, html_url: `${url}/pull/${state.pullRequests.length + 1}`, state: 'open',
          title: body.title, body: body.body,
          head: { ref: head, label: `${headOwner}:${head}`, repo: { owner: { login: headOwner }, name: headName, full_name: `${headOwner}/${headName}` } },
          base: { ref: body.base, repo: { owner: { login: baseOwner }, name: baseName, full_name: `${baseOwner}/${baseName}` } } };
        state.pullRequests.push(pr);
        return send(pr, 201);
      }
    }
    if (/\/pulls\/\d+$/.test(parsedUrl.pathname) && req.method === 'PATCH') {
      const pr = state.pullRequests.find((item) => item.number === Number(parsedUrl.pathname.split('/').at(-1)));
      if (!pr) return send({ message: 'Not found' }, 404);
      Object.assign(pr, body);
      return send(pr);
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
        '': { name: 'fixture-app', version: '1.0.0', dependencies: Object.fromEntries(packageNames.map((name) => [name, '1.0.0'])) },
        ...Object.fromEntries(packageNames.map((name) => [`node_modules/${name}`, {
          version: '1.0.0', resolved: `${url}/${name}/-/1.0.0.tgz`, integrity: tarballs.get(name).get('1.0.0').integrity,
          ...(dependenciesByPackage[name] ? { dependencies: dependenciesByPackage[name] } : {}),
        }])),
      } };
    },
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
