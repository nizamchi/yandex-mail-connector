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

test('TOOLS is a non-empty array of length 10', () => {
  assert.ok(Array.isArray(TOOLS));
  assert.equal(TOOLS.length, 10, `expected 10 v1 tools, got ${TOOLS.length}`);
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
  assert.equal(wouldRegister(TOOLS, 0).length, 6, 'L0 must expose 6 read-tools');
  assert.equal(wouldRegister(TOOLS, 1).length, 9, 'L1 must expose 9 tools');
  assert.equal(wouldRegister(TOOLS, 2).length, 10, 'L2 must expose all 10 tools');
  assert.equal(wouldRegister(TOOLS, 3).length, 10, 'L3 must expose all 10 tools');
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
  assert.equal(visibleAtL3.length, 10,
    'dummy with authLevel=99 must NOT be in L3 registration set');
  assert.ok(!visibleAtL3.some(t => t.name === 'yandex_dummy_forbidden'),
    'dummy must be filtered out by predicate');
});

test('tool names are unique', () => {
  const names = TOOLS.map(t => t.name);
  const unique = new Set(names);
  assert.equal(unique.size, names.length, 'duplicate tool names detected');
});

test('authLevel matrix: send_email=2; mark/move/delete=1; rest=0', () => {
  const byName = new Map(TOOLS.map(t => [t.name, t]));
  assert.equal(byName.get('yandex_send_email')?.requires.authLevel, 2);
  assert.equal(byName.get('yandex_mark_email')?.requires.authLevel, 1);
  assert.equal(byName.get('yandex_move_email')?.requires.authLevel, 1);
  assert.equal(byName.get('yandex_delete_email')?.requires.authLevel, 1);
  for (const readTool of [
    'yandex_list_folders',
    'yandex_folder_status',
    'yandex_list_emails',
    'yandex_get_email',
    'yandex_search_emails',
    'yandex_get_special_folders',
  ]) {
    assert.equal(byName.get(readTool)?.requires.authLevel, 0,
      `${readTool} must be L0`);
  }
});
