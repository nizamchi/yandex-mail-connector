// cli-index.ts -- `yandex-mail-mcp index <command>` subcommand (Layer 2).
//
// Thin CLI over mail-index.ts so a human (or a cron job) can build and refresh
// the local search index out-of-band from the MCP server process. Invoked from
// index.ts BEFORE the server boots, so it never opens the allowlist/policy
// startup gates. build/update connect to IMAP via the default source;
// status/drop are local-only.

import * as mailIndex from './mail-index.js';

function printStatus(): void {
  const s = mailIndex.getIndexStatus();
  process.stdout.write(`Mail index: ${s.exists ? 'present' : 'empty'}\n`);
  process.stdout.write(`  account:  ${s.account}\n`);
  process.stdout.write(`  location: ${s.indexPath}\n`);
  process.stdout.write(`  total:    ${s.totalCount} messages across ${s.folders.length} folder(s)\n`);
  if (s.exists) {
    process.stdout.write(
      `  threads:  ${s.threadingReady
        ? 'ready (In-Reply-To links present)'
        : 'subject-only -- run `index update` to add Message-ID links'}\n`,
    );
  }
  for (const f of s.folders) {
    const when = f.lastSyncMs ? new Date(f.lastSyncMs).toISOString() : 'never';
    process.stdout.write(`    - ${f.folder}: ${f.count} msg (uidNext=${f.uidNext}, synced ${when})\n`);
  }
}

function reportErrors(errors: mailIndex.IndexError[]): void {
  for (const e of errors) {
    process.stderr.write(`[index] FAILED ${e.folder}: ${e.error}\n`);
  }
}

function usage(): void {
  process.stderr.write(
    'Usage: yandex-mail-mcp index <command>\n' +
    '  status              show index location, account, per-folder counts\n' +
    '  build [folder...]   full (re)build of folders (default: INBOX)\n' +
    '  update [folder...]  incremental sync (default: all indexed folders)\n' +
    '  drop                delete the index\n',
  );
}

export async function runIndexCli(args: string[]): Promise<number> {
  const sub = args[0];
  const rest = args.slice(1);
  switch (sub) {
    case 'status':
      printStatus();
      return 0;

    case 'build': {
      const folders = rest.length > 0 ? rest : ['INBOX'];
      // A bare `index build` covers only INBOX; cross-folder threads (the
      // headline get_thread feature) also need Sent indexed.
      if (rest.length === 0) {
        process.stderr.write('[index] note: indexing INBOX only -- add folders for cross-folder threads, e.g. `index build INBOX Sent`.\n');
      }
      process.stderr.write(`[index] building ${folders.join(', ')} ...\n`);
      const r = await mailIndex.buildIndex(folders);
      process.stderr.write(`[index] indexed ${r.added} message(s).\n`);
      reportErrors(r.errors);
      printStatus();
      return r.errors.length > 0 ? 1 : 0;
    }

    case 'update': {
      let folders = rest;
      if (folders.length === 0) {
        folders = mailIndex.getIndexStatus().folders.map(f => f.folder);
        if (folders.length === 0) {
          process.stderr.write('[index] nothing to update -- run `index build <folder>` first.\n');
          return 1;
        }
      }
      process.stderr.write(`[index] updating ${folders.join(', ')} ...\n`);
      const r = await mailIndex.updateIndex(folders);
      process.stderr.write(`[index] added ${r.added} new message(s).\n`);
      reportErrors(r.errors);
      printStatus();
      return r.errors.length > 0 ? 1 : 0;
    }

    case 'drop':
      mailIndex.dropIndex();
      process.stderr.write('[index] dropped.\n');
      return 0;

    default:
      usage();
      return sub === undefined ? 1 : 2;
  }
}
