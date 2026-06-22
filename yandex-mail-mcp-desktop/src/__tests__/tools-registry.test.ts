import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { z } from 'zod';
import { TOOLS, type ToolDef } from '../tools.js';
import type { AuthLevel } from '../auth.js';

// Filtering predicate — DUPLICATED from registerTools intentionally. Keeping
// this test independent of McpServer avoids the heavy SDK mock surface and
// makes the predicate itself the assertion target.
function wouldRegister(tools: ToolDef[], authLevel: AuthLevel): ToolDef[] {
  return tools.filter(t => authLevel >= t.requires.authLevel);
}

test('TOOLS is a non-empty array of length 20', () => {
  // 10 v1 tools + 1 v2 trust_address (Phase 5) + 1 v2.1.4 yandex_health_check
  // + 1 v2.3.0 yandex_stats + 1 v2.4.0 yandex_find_sender
  // + 2 v2.5.0 (yandex_count + yandex_folder_peek)
  // + 2 v2.6.0 (yandex_search_fast + yandex_get_thread)
  // + 1 v2.8.0 k20 (yandex_unanswered)
  // + 1 260622-psg (yandex_get_attachment).
  assert.ok(Array.isArray(TOOLS));
  assert.equal(TOOLS.length, 20, `expected 20 tools, got ${TOOLS.length}`);
});

test('every tool name starts with yandex_', () => {
  for (const t of TOOLS) {
    assert.ok(t.name.startsWith('yandex_'), `tool ${t.name} must start with yandex_`);
  }
});

test('all requires.authLevel are in {0,1,2,3}', () => {
  for (const t of TOOLS) {
    assert.ok([0, 1, 2, 3].includes(t.requires.authLevel),
      `${t.name}: invalid authLevel ${t.requires.authLevel}`);
  }
});

test('registration counts per level', () => {
  // L0 = 6 v1 read-only + health_check + stats + find_sender + count + folder_peek
  //      + search_fast + get_thread + unanswered + get_attachment = 15.
  // L1 = 15 + (mark, move, delete, trust_address) = 19.
  // L2/L3 = +send_email = 20.
  assert.equal(wouldRegister(TOOLS, 0).length, 15, 'L0 must expose 15 read-tools');
  assert.equal(wouldRegister(TOOLS, 1).length, 19, 'L1 must expose 19 tools');
  assert.equal(wouldRegister(TOOLS, 2).length, 20, 'L2 must expose all 20 tools');
  assert.equal(wouldRegister(TOOLS, 3).length, 20, 'L3 must expose all 20 tools');
});

test('dummy authLevel=99 tool is NEVER registered (even at L3)', () => {
  const dummy: ToolDef = {
    name: 'yandex_dummy_forbidden',
    title: '',
    description: '',
    inputSchema: z.object({}).strict(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    // Cast through unknown — by design 99 is outside AuthLevel union; this test
    // proves the predicate gate stops it regardless of type-system promises.
    requires: { authLevel: 99 as unknown as AuthLevel },
    handler: async () => ({ content: [] as Array<{ type: 'text'; text: string }> }),
  };
  const extended = [...TOOLS, dummy];
  const visibleAtL3 = wouldRegister(extended, 3);
  assert.equal(visibleAtL3.length, 20,
    'dummy with authLevel=99 must NOT be in L3 registration set');
  assert.ok(!visibleAtL3.some(t => t.name === 'yandex_dummy_forbidden'),
    'dummy must be filtered out by predicate');
});

test('tool names are unique', () => {
  const names = TOOLS.map(t => t.name);
  const unique = new Set(names);
  assert.equal(unique.size, names.length, 'duplicate tool names detected');
});

test('yandex_send_email schema accepts confirmation_token and dry_run as optional', () => {
  const byName = new Map(TOOLS.map(t => [t.name, t]));
  const def = byName.get('yandex_send_email');
  assert.ok(def, 'send_email must exist');
  const schema = def.inputSchema;

  // Minimal valid params — must parse.
  assert.doesNotThrow(() => schema.parse({ to: ['a@x'], subject: 's', text: 't' }));
  // With 6-digit token — must parse.
  assert.doesNotThrow(() => schema.parse({ to: ['a@x'], subject: 's', text: 't', confirmation_token: '123456' }));
  // With dry_run=true — must parse.
  assert.doesNotThrow(() => schema.parse({ to: ['a@x'], subject: 's', text: 't', dry_run: true }));
  // Non-6-digit token — must reject.
  assert.throws(() => schema.parse({ to: ['a@x'], subject: 's', text: 't', confirmation_token: 'abc' }));
  // Token with wrong digit count — must reject.
  assert.throws(() => schema.parse({ to: ['a@x'], subject: 's', text: 't', confirmation_token: '12345' }));
  // dry_run as string — must reject.
  assert.throws(() => schema.parse({ to: ['a@x'], subject: 's', text: 't', dry_run: 'yes' }));
});

// R7 (v2.6.0): permanent delete is gated by a server-issued confirmation code,
// carried back via the same 6-digit confirmation_token field as send.
test('yandex_delete_email schema accepts 6-digit confirmation_token (R7)', () => {
  const byName = new Map(TOOLS.map(t => [t.name, t]));
  const def = byName.get('yandex_delete_email');
  assert.ok(def, 'delete_email must exist');
  const schema = def.inputSchema;

  // Recoverable delete, no token — must parse.
  assert.doesNotThrow(() => schema.parse({ uid: 1 }));
  // Permanent delete with a 6-digit token — must parse.
  assert.doesNotThrow(() => schema.parse({ uid: 1, permanent: true, confirmation_token: '123456' }));
  // Non-numeric token — must reject.
  assert.throws(() => schema.parse({ uid: 1, permanent: true, confirmation_token: 'abcdef' }));
  // Wrong digit count — must reject.
  assert.throws(() => schema.parse({ uid: 1, permanent: true, confirmation_token: '12345' }));
});

test('authLevel matrix: send_email=2; mark/move/delete=1; rest=0', () => {
  const byName = new Map(TOOLS.map(t => [t.name, t]));
  assert.equal(byName.get('yandex_send_email')?.requires.authLevel, 2);
  assert.equal(byName.get('yandex_mark_email')?.requires.authLevel, 1);
  assert.equal(byName.get('yandex_move_email')?.requires.authLevel, 1);
  assert.equal(byName.get('yandex_delete_email')?.requires.authLevel, 1);
  assert.equal(byName.get('yandex_trust_address')?.requires.authLevel, 1, 'trust_address must be L1');
  for (const readTool of [
    'yandex_list_folders',
    'yandex_folder_status',
    'yandex_list_emails',
    'yandex_get_email',
    'yandex_search_emails',
    'yandex_get_special_folders',
    'yandex_stats',
    'yandex_find_sender',
    'yandex_count',
    'yandex_folder_peek',
    'yandex_search_fast',
    'yandex_get_thread',
    'yandex_unanswered',
    'yandex_get_attachment',
  ]) {
    assert.equal(byName.get(readTool)?.requires.authLevel, 0,
      `${readTool} must be L0`);
  }
});
