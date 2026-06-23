#!/usr/bin/env node
// Install the connector's slash commands (/ymc-info, /ymc-config, /ymc-index,
// /ymc-update, /ymc-trust, /ymc-doctor) into the user's Claude Code commands
// directory (~/.claude/commands/). Cross-platform.
//
// Usage:
//   node bin/install-slash.js          # install (skip if up-to-date)
//   node bin/install-slash.js --force  # overwrite even if up-to-date
//   node bin/install-slash.js --uninstall

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const FORCE = process.argv.includes('--force');
const UNINSTALL = process.argv.includes('--uninstall');

// Source: the slash command files are tracked in the repo under
// <repo-root>/.claude/commands/. This script lives in
// <repo-root>/yandex-mail-mcp-desktop/bin/install-slash.js. Resolve repo
// root from __dirname.
const repoRoot = path.resolve(__dirname, '..', '..');
const sourceDir = path.join(repoRoot, '.claude', 'commands');
const targetDir = path.join(os.homedir(), '.claude', 'commands');

// Commands shipped by this connector = every .md in the repo's .claude/commands/.
// Globbed (not a hardcoded list) so a newly added command installs without
// anyone remembering to edit this file. Empty if the source dir is absent
// (install() reports that case with a friendly error below).
const COMMANDS = exists(sourceDir)
  ? fs.readdirSync(sourceDir).filter(f => f.endsWith('.md')).sort()
  : [];

function exists(p) {
  try { fs.accessSync(p); return true; } catch { return false; }
}

function sameContent(a, b) {
  try {
    return fs.readFileSync(a, 'utf8') === fs.readFileSync(b, 'utf8');
  } catch { return false; }
}

function uninstall() {
  let removed = 0;
  for (const cmd of COMMANDS) {
    const dst = path.join(targetDir, cmd);
    if (exists(dst)) {
      try { fs.unlinkSync(dst); removed += 1; console.log(`removed: ${dst}`); }
      catch (e) { console.error(`failed to remove ${dst}: ${e.message}`); }
    }
  }
  if (removed === 0) console.log('nothing to remove');
  else console.log(`\nDone. Removed ${removed} command(s). Restart Claude Code to refresh.`);
}

function install() {
  if (!exists(sourceDir)) {
    console.error(`source directory not found: ${sourceDir}`);
    console.error('(expected to find the repo .claude/commands/ — are you running this from a clone of the repo?)');
    process.exit(1);
  }

  fs.mkdirSync(targetDir, { recursive: true });

  let installed = 0;
  let skipped = 0;
  let updated = 0;
  for (const cmd of COMMANDS) {
    const src = path.join(sourceDir, cmd);
    const dst = path.join(targetDir, cmd);
    if (!exists(src)) {
      console.warn(`source missing: ${src} — skipping`);
      continue;
    }
    if (exists(dst) && !FORCE) {
      if (sameContent(src, dst)) {
        skipped += 1;
        console.log(`up-to-date: ${cmd}`);
        continue;
      } else {
        // Different content; without --force, refuse to overwrite (user might
        // have customised). With --force, replace.
        console.log(`differs: ${cmd} (use --force to overwrite)`);
        skipped += 1;
        continue;
      }
    }
    const action = exists(dst) ? 'updated' : 'installed';
    try {
      fs.copyFileSync(src, dst);
      if (action === 'updated') updated += 1; else installed += 1;
      console.log(`${action}: ${dst}`);
    } catch (e) {
      console.error(`failed to copy ${cmd}: ${e.message}`);
    }
  }

  console.log('');
  console.log(`Done. Installed: ${installed}, updated: ${updated}, skipped: ${skipped}.`);
  if (installed + updated > 0) {
    console.log('Restart Claude Code (/exit then `claude`) to load the new commands.');
  }
  // Onboarding funnel: /ymc-info is the guided tour. Point first-timers at it
  // here (the last step of install) so they don't have to discover it.
  console.log('First step after restart: type /ymc-info — a guided tour of what the connector can do.');
}

if (UNINSTALL) uninstall();
else install();
