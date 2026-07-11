#!/usr/bin/env node
/**
 * Pack the package into a tarball, install it into a throwaway project, and
 * assert that:
 *   1. dist/index.d.ts ships inside the tarball.
 *   2. CommonJS `require()` exposes the named exports.
 *   3. Native ESM `import { ... }` resolves the same names (catches the
 *      "member-expression export" bug where cjs-module-lexer can't see the
 *      names for ESM consumers).
 *
 * webhook-kit has ZERO runtime dependencies (Node `crypto` + global `fetch`),
 * so the throwaway consumer installs only the tarball.
 *
 * Exits non-zero with a clear message on any failure.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const pkgRoot = new URL('..', import.meta.url).pathname;
const pkg = JSON.parse(readFileSync(join(pkgRoot, 'package.json'), 'utf8'));

const EXPECTED = [
  'generateOpaqueToken',
  'hashOpaqueToken',
  'verifyOpaqueToken',
  'generateResetToken',
  'hashResetToken',
  'prehashPassword',
  'createPasswordHasher',
  'createRefreshToken',
  'rotateRefreshToken',
  'revokeRefreshToken',
  'isEpochValid',
  'createMemoryRefreshTokenStore',
];

function run(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { encoding: 'utf8', ...opts });
}

function fail(message) {
  console.error(`\n[verify:pack] FAIL: ${message}\n`);
  process.exit(1);
}

const workDir = mkdtempSync(join(tmpdir(), 'auth-verify-'));
let tarballPath;

try {
  console.log('[verify:pack] Building...');
  run('npm', ['run', 'build'], { cwd: pkgRoot, stdio: 'inherit' });

  if (!existsSync(join(pkgRoot, 'dist', 'index.d.ts'))) {
    fail('dist/index.d.ts is missing after build');
  }

  console.log('[verify:pack] Packing tarball...');
  const packOut = run('npm', ['pack', '--json', '--pack-destination', workDir], { cwd: pkgRoot });
  const filename = JSON.parse(packOut)[0].filename;
  tarballPath = join(workDir, filename);

  // 1. Assert the declaration file ships inside the tarball.
  const contents = run('tar', ['-tzf', tarballPath]);
  if (!contents.includes('package/dist/index.d.ts')) {
    fail('dist/index.d.ts is not present in the packed tarball');
  }
  console.log('[verify:pack] OK: dist/index.d.ts ships in tarball');

  // Throwaway consumer — zero peer deps.
  const consumerDir = join(workDir, 'consumer');
  run('mkdir', ['-p', consumerDir]);
  writeFileSync(
    join(consumerDir, 'package.json'),
    JSON.stringify({ name: 'whk-consumer', version: '1.0.0', private: true }, null, 2),
  );

  console.log('[verify:pack] Installing tarball into consumer...');
  run('npm', ['install', '--no-audit', '--no-fund', tarballPath], { cwd: consumerDir, stdio: 'inherit' });

  const names = JSON.stringify(EXPECTED);

  // 2. CommonJS require smoke.
  const cjsSmoke = `
    const mod = require('${pkg.name}');
    const missing = ${names}.filter((n) => typeof mod[n] !== 'function');
    if (missing.length) { console.error('CJS missing exports: ' + missing.join(', ')); process.exit(2); }
    console.log('CJS OK');
  `;
  writeFileSync(join(consumerDir, 'smoke.cjs'), cjsSmoke);
  if (!run('node', ['smoke.cjs'], { cwd: consumerDir }).includes('CJS OK')) {
    fail('CommonJS smoke did not report OK');
  }
  console.log('[verify:pack] OK: CommonJS require exposes named exports');

  // 3. Native ESM import smoke.
  const esmSmoke = `
    import * as mod from '${pkg.name}';
    const missing = ${names}.filter((n) => typeof mod[n] !== 'function');
    if (missing.length) { console.error('ESM missing: ' + missing.join(', ')); process.exit(5); }
    console.log('ESM OK');
  `;
  writeFileSync(join(consumerDir, 'smoke.mjs'), esmSmoke);
  if (!run('node', ['smoke.mjs'], { cwd: consumerDir }).includes('ESM OK')) {
    fail('ESM smoke did not report OK');
  }
  console.log('[verify:pack] OK: ESM named imports resolve');

  console.log('\n[verify:pack] PASS: all checks green');
} finally {
  try {
    rmSync(workDir, { recursive: true, force: true });
  } catch {
    // ignore cleanup errors
  }
}
