import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { createDefinitions } from '../index.js'
const manifestJson = await readFile(new URL('../examples/bound.json', import.meta.url), 'utf8'); const definitions = createDefinitions(); assert.deepEqual(definitions.map(row => row.name), ['dsh_principal_binding_inspect', 'dsh_principal_binding_verify']); assert.equal((await definitions[0].execute({ manifestJson })).nodeCount, 6); process.stdout.write('plugin smoke: 2 DSH definitions, inspect ok\n')
