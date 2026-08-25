import { createHash } from 'node:crypto'
import { lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises'
import { isAbsolute, relative, resolve } from 'node:path'

const MAX_FILE = 4 * 1024 * 1024
const HEX = /^[a-f0-9]{64}$/
const ID = /^[a-z0-9][a-z0-9._-]{0,127}$/
const KINDS = ['principal', 'session', 'agent', 'tool-call', 'runtime', 'artifact']
const RELATIONS = ['initiates', 'delegates', 'invokes', 'executes', 'produces']
const SECRET_VALUE = /(?:bearer\s+[a-z0-9._-]{12,}|(?:sk|ghp|github_pat)_[a-z0-9_-]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i
const stable = value => JSON.stringify(value, (_, child) => child && typeof child === 'object' && !Array.isArray(child) ? Object.fromEntries(Object.entries(child).sort(([a], [b]) => a.localeCompare(b))) : child)
export const sha256 = value => createHash('sha256').update(value).digest('hex')
const fail = (code, message) => Object.assign(new Error(message), { code })
const boundedId = (value, label) => { if (typeof value !== 'string' || !ID.test(value)) throw fail('INVALID_MANIFEST', `${label} must be a bounded public id`) }
const hash = (value, label) => { if (!HEX.test(value || '')) throw fail('INVALID_MANIFEST', `${label} must be lowercase SHA-256`) }
const timestamp = (value, label) => { const parsed = Date.parse(value); if (!Number.isFinite(parsed)) throw fail('INVALID_TIME', `${label} must be an ISO timestamp`); return parsed }

function rejectSecrets(value, path = '$') {
  if (typeof value === 'string' && SECRET_VALUE.test(value)) throw fail('SECRET_MATERIAL', `secret-shaped value rejected at ${path}`)
  if (!value || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) {
    if (/(?:secret|password|credential|api[_-]?key|private[_-]?key|authorization|cookie|email|username)$/i.test(key) && (typeof child === 'string' || typeof child === 'number')) throw fail('SECRET_MATERIAL', `identity or credential field rejected at ${path}.${key}`)
    rejectSecrets(child, `${path}.${key}`)
  }
}

function hasCycle(nodeIds, bindings) {
  const graph = new Map([...nodeIds].map(id => [id, []]))
  for (const edge of bindings) graph.get(edge.from)?.push(edge.to)
  const visiting = new Set(); const visited = new Set()
  const visit = id => { if (visiting.has(id)) return true; if (visited.has(id)) return false; visiting.add(id); for (const next of graph.get(id) || []) if (visit(next)) return true; visiting.delete(id); visited.add(id); return false }
  return [...nodeIds].some(visit)
}

function parseManifest(input) {
  let manifest
  try { manifest = typeof input === 'string' ? JSON.parse(input) : structuredClone(input) } catch { throw fail('INVALID_MANIFEST', 'manifest must be JSON') }
  if (!manifest || manifest.schemaVersion !== 1) throw fail('INVALID_MANIFEST', 'schemaVersion 1 required')
  rejectSecrets(manifest)
  boundedId(manifest.proofId, 'proofId'); boundedId(manifest.expected?.targetRevision, 'expected.targetRevision')
  for (const key of ['authorityHash', 'tenantHash', 'terminalArtifactSha256']) hash(manifest.expected?.[key], `expected.${key}`)
  const evaluationMs = timestamp(manifest.evaluationTime, 'evaluationTime')
  const maxAgeMs = manifest.policy?.maxEvidenceAgeMs
  if (!Number.isInteger(maxAgeMs) || maxAgeMs < 1000 || maxAgeMs > 365 * 86400000) throw fail('INVALID_MANIFEST', 'maxEvidenceAgeMs is out of range')
  if (!Number.isInteger(manifest.policy?.minimumKeyEpoch) || manifest.policy.minimumKeyEpoch < 0 || manifest.policy.minimumKeyEpoch > 1000000) throw fail('INVALID_MANIFEST', 'minimumKeyEpoch is invalid')
  if (manifest.policy?.requireSingleTenant !== true || manifest.policy?.requireUniqueChain !== true) throw fail('INVALID_MANIFEST', 'single tenant and unique chain policies must be true')
  if (!Array.isArray(manifest.policy?.allowedIssuerHashes) || !manifest.policy.allowedIssuerHashes.length || manifest.policy.allowedIssuerHashes.length > 32) throw fail('INVALID_MANIFEST', '1..32 allowedIssuerHashes required')
  const allowedIssuers = new Set(); for (const issuer of manifest.policy.allowedIssuerHashes) { hash(issuer, 'allowedIssuerHash'); allowedIssuers.add(issuer) }
  if (!Array.isArray(manifest.nodes) || manifest.nodes.length !== KINDS.length) throw fail('INVALID_MANIFEST', 'exactly six binding nodes required')
  const nodes = new Map(); const kindNodes = new Map()
  for (const node of manifest.nodes) {
    boundedId(node?.id, 'node.id')
    if (!KINDS.includes(node.kind) || kindNodes.has(node.kind) || nodes.has(node.id)) throw fail('INVALID_MANIFEST', 'node kinds and ids must be unique and complete')
    for (const key of ['authorityHash', 'tenantHash', 'surfaceIdentityHash', 'sourceSha256']) hash(node[key], `node.${key}`)
    boundedId(node.targetRevision, 'node.targetRevision')
    if (!Number.isInteger(node.keyEpoch) || node.keyEpoch < 0 || node.keyEpoch > 1000000) throw fail('INVALID_MANIFEST', 'node.keyEpoch is invalid')
    const observedMs = timestamp(node.observedAt, 'node.observedAt')
    nodes.set(node.id, { node, observedMs }); kindNodes.set(node.kind, node)
  }
  if (KINDS.some(kind => !kindNodes.has(kind))) throw fail('INVALID_MANIFEST', 'all required node kinds must be present')
  if (!Array.isArray(manifest.bindings) || manifest.bindings.length !== RELATIONS.length) throw fail('INVALID_MANIFEST', 'exactly five adjacent bindings required')
  const bindingIds = new Set(); const pairBindings = new Map()
  for (const binding of manifest.bindings) {
    boundedId(binding?.id, 'binding.id'); if (bindingIds.has(binding.id)) throw fail('INVALID_MANIFEST', 'duplicate binding id'); bindingIds.add(binding.id)
    if (!nodes.has(binding.from) || !nodes.has(binding.to) || !RELATIONS.includes(binding.relation)) throw fail('INVALID_MANIFEST', 'binding endpoint or relation is invalid')
    hash(binding.issuerHash, 'binding.issuerHash'); hash(binding.assertionSha256, 'binding.assertionSha256')
    const validFromMs = timestamp(binding.validFrom, 'binding.validFrom'); const validUntilMs = timestamp(binding.validUntil, 'binding.validUntil')
    if (validUntilMs < validFromMs || typeof binding.revoked !== 'boolean') throw fail('INVALID_MANIFEST', 'binding validity is invalid')
    const pair = `${binding.from}->${binding.to}`; if (pairBindings.has(pair)) throw fail('INVALID_MANIFEST', 'duplicate binding pair')
    pairBindings.set(pair, { binding, validFromMs, validUntilMs })
  }
  return { manifest, evaluationMs, allowedIssuers, nodes, kindNodes, pairBindings, cyclic: hasCycle(nodes.keys(), manifest.bindings) }
}

export function inspectPrincipalBindingManifestJson(manifestJson) {
  const { manifest } = parseManifest(manifestJson)
  return { schemaVersion: 1, proofIdHash: sha256(manifest.proofId), authorityHash: manifest.expected.authorityHash, tenantHash: manifest.expected.tenantHash, targetRevisionHash: sha256(manifest.expected.targetRevision), nodeCount: manifest.nodes.length, bindingCount: manifest.bindings.length, returnsIdentities: false, authenticatesPrincipals: false, executesExternalCommands: false }
}

export function evaluatePrincipalBindingManifest(manifestJson) {
  const { manifest, evaluationMs, allowedIssuers, nodes, kindNodes, pairBindings, cyclic } = parseManifest(manifestJson)
  const nodeResults = KINDS.map(kind => {
    const node = kindNodes.get(kind); const observedMs = nodes.get(node.id).observedMs
    const authorityMatched = node.authorityHash === manifest.expected.authorityHash
    const tenantMatched = node.tenantHash === manifest.expected.tenantHash
    const revisionMatched = node.targetRevision === manifest.expected.targetRevision
    const fresh = observedMs <= evaluationMs && evaluationMs - observedMs <= manifest.policy.maxEvidenceAgeMs
    const keyEpochSatisfied = node.keyEpoch >= manifest.policy.minimumKeyEpoch
    const terminalMatched = kind !== 'artifact' || node.surfaceIdentityHash === manifest.expected.terminalArtifactSha256
    return { kind, nodeIdHash: sha256(node.id), surfaceIdentityHash: node.surfaceIdentityHash, sourceSha256: node.sourceSha256, authorityMatched, tenantMatched, revisionMatched, fresh, keyEpoch: node.keyEpoch, keyEpochSatisfied, terminalMatched, bound: authorityMatched && tenantMatched && revisionMatched && fresh && keyEpochSatisfied && terminalMatched }
  })
  const bindingResults = RELATIONS.map((relation, index) => {
    const from = kindNodes.get(KINDS[index]); const to = kindNodes.get(KINDS[index + 1]); const item = pairBindings.get(`${from.id}->${to.id}`)
    if (!item) return { relation, present: false, valid: false }
    const { binding, validFromMs, validUntilMs } = item
    const relationMatched = binding.relation === relation; const issuerAllowed = allowedIssuers.has(binding.issuerHash); const active = validFromMs <= evaluationMs && evaluationMs <= validUntilMs && !binding.revoked
    return { relation, bindingIdHash: sha256(binding.id), assertionSha256: binding.assertionSha256, issuerHash: binding.issuerHash, present: true, relationMatched, issuerAllowed, active, valid: relationMatched && issuerAllowed && active }
  })
  const exactChain = manifest.bindings.length === RELATIONS.length && bindingResults.every(row => row.present) && !cyclic
  const verified = exactChain && nodeResults.every(row => row.bound) && bindingResults.every(row => row.valid)
  return { schemaVersion: 1, verdict: verified ? 'bound' : 'unbound', proofIdHash: sha256(manifest.proofId), authorityHash: manifest.expected.authorityHash, tenantHash: manifest.expected.tenantHash, targetRevisionHash: sha256(manifest.expected.targetRevision), checks: { exactUniqueAcyclicChain: exactChain, allNodesBound: nodeResults.every(row => row.bound), allBindingsValid: bindingResults.every(row => row.valid) }, disclosures: { cyclic }, nodes: nodeResults, bindings: bindingResults, returnsIdentities: false, authenticatesPrincipals: false, grantsAuthority: false, executesExternalCommands: false, destructiveActions: false }
}

async function safeManifest(root, manifestPath) {
  if (typeof manifestPath !== 'string' || !manifestPath || manifestPath.length > 512 || isAbsolute(manifestPath)) throw fail('PATH_ESCAPE', 'manifestPath must be bounded and workspace-relative')
  const absolute = resolve(root, manifestPath); const rel = relative(root, absolute)
  if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw fail('PATH_ESCAPE', 'manifestPath escapes workspaceRoot')
  let cursor = root; let stat
  const parts = rel.split(/[\\/]/)
  for (const [index, part] of parts.entries()) { cursor = resolve(cursor, part); stat = await lstat(cursor).catch(() => { throw fail('MISSING_MANIFEST', 'manifest is missing') }); if (stat.isSymbolicLink()) throw fail('UNSAFE_MANIFEST', 'manifest path must contain no symlink'); if (index < parts.length - 1 && !stat.isDirectory()) throw fail('UNSAFE_MANIFEST', 'manifest parent must be a real directory') }
  if (!stat.isFile() || stat.size > MAX_FILE) throw fail('UNSAFE_MANIFEST', 'manifest must be a regular file no larger than 4 MiB')
  const rootReal = await realpath(root); const fileReal = await realpath(absolute); const realRel = relative(rootReal, fileReal)
  if (realRel.startsWith('..') || isAbsolute(realRel)) throw fail('PATH_ESCAPE', 'real manifest path escapes workspaceRoot')
  return readFile(fileReal, 'utf8')
}

async function safeArtifactDir(root, artifactDir) {
  if (typeof artifactDir !== 'string' || !artifactDir || artifactDir.length > 512 || isAbsolute(artifactDir)) throw fail('PATH_ESCAPE', 'artifactDir must be bounded and workspace-relative')
  const dir = resolve(root, artifactDir); const rel = relative(root, dir)
  if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw fail('PATH_ESCAPE', 'artifactDir escapes workspaceRoot')
  let cursor = root
  for (const part of rel.split(/[\\/]/)) { cursor = resolve(cursor, part); try { const stat = await lstat(cursor); if (stat.isSymbolicLink() || !stat.isDirectory()) throw fail('UNSAFE_ARTIFACT_DIR', 'artifactDir components must be real directories') } catch (error) { if (error.code !== 'ENOENT') throw error; await mkdir(cursor) } }
  return dir
}

export async function verifyPrincipalBindingManifest({ workspaceRoot, manifestPath, artifactDir }) {
  const root = resolve(workspaceRoot); const report = evaluatePrincipalBindingManifest(await safeManifest(root, manifestPath)); const bytes = Buffer.from(`${stable(report)}\n`); const digest = sha256(bytes); const dir = await safeArtifactDir(root, artifactDir); const output = resolve(dir, `principal-binding-proof-${digest}.json`)
  try { await writeFile(output, bytes, { flag: 'wx' }) } catch (error) { if (error.code !== 'EEXIST') throw error; const existing = await readFile(output); if (!existing.equals(bytes)) throw fail('ARTIFACT_DIVERGED', 'content-addressed artifact diverged') }
  const readBack = await readFile(output); if (sha256(readBack) !== digest) throw fail('READBACK_FAILED', 'artifact read-back verification failed')
  return { ...report, artifact: { path: relative(root, output).replaceAll('\\', '/'), sha256: digest, verifiedByReadBack: true } }
}
