import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fetchPublishedVersions } from '../src/collectors/npm-versions.js';
import { fixturePackage, startRegistry } from './fixtures/registry.js';

test('fetchPublishedVersions uses the worktree npm registry and returns only stable semver releases', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-versions-test-'));
  const registry = await startRegistry(directory, {
    versions: ['1.0.1', '1.0.1-beta.1', '1.0.0'],
  });
  const previous = new Map(Object.entries(registry.env).map(([key]) => [key, process.env[key]]));
  let closed = false;
  try {
    for (const [key, value] of Object.entries(registry.env)) process.env[key] = value;
    const catalogs = await fetchPublishedVersions(directory, [fixturePackage, 'invalid package name']);
    assert.deepEqual(catalogs.get(fixturePackage), { versions: ['1.0.0', '1.0.1'], error: null });
    assert.equal(catalogs.get('invalid package name').versions, null);
    assert.match(catalogs.get('invalid package name').error, /Invalid npm package name/);
    assert.ok(registry.requests.some((request) => request.path.startsWith(`/${fixturePackage}`)));
    assert.equal(registry.requests.filter((request) => request.path.startsWith(`/${fixturePackage}`)).length, 1);
    await registry.close();
    closed = true;
    const failed = await fetchPublishedVersions(directory, ['unavailable-fixture']);
    assert.equal(failed.get('unavailable-fixture').versions, null);
    assert.match(failed.get('unavailable-fixture').error, /npm view failed.*registry release catalog is unavailable/);
  } finally {
    for (const [key, value] of previous) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    if (!closed) await registry.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
