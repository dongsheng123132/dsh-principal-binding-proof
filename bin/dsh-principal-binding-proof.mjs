#!/usr/bin/env node
import { readFile } from 'node:fs/promises'
import { evaluatePrincipalBindingManifest, inspectPrincipalBindingManifestJson } from '../lib/principal-binding-proof.mjs'
const [command, manifestPath] = process.argv.slice(2)
if (!['inspect', 'verify'].includes(command) || !manifestPath) { process.stderr.write('Usage: dsh-principal-binding-proof <inspect|verify> <manifest.json>\n'); process.exit(2) }
try { const json = await readFile(manifestPath, 'utf8'); const result = command === 'inspect' ? inspectPrincipalBindingManifestJson(json) : evaluatePrincipalBindingManifest(json); process.stdout.write(`${JSON.stringify(result)}\n`); process.exitCode = command === 'verify' && result.verdict !== 'bound' ? 1 : 0 } catch (error) { process.stdout.write(`${JSON.stringify({ ok: false, error: { code: error.code || 'ERROR' } })}\n`); process.exitCode = 2 }
