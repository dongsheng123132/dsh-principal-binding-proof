import { inspectPrincipalBindingManifestJson, verifyPrincipalBindingManifest } from './lib/principal-binding-proof.mjs'
export const name = 'dsh-principal-binding-proof'; export const inject = ['tools']
const renderJson = (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }]; const define = value => ({ ...value, output: { schema: {}, render: renderJson } })
export function createDefinitions(_ctx = {}, config = {}) {
  const workspaceRoot = config.workspaceRoot || process.cwd()
  return [
    define({ name: 'dsh_principal_binding_inspect', description: 'Inspect bounded hashes and counts from an explicit pseudonymous principal-binding manifest.', parameters: { type: 'object', required: ['manifestJson'], properties: { manifestJson: { type: 'string' } }, additionalProperties: false }, execute: async ({ manifestJson }) => inspectPrincipalBindingManifestJson(manifestJson) }),
    define({ name: 'dsh_principal_binding_verify', description: 'Verify a redacted DSH authority-binding chain and write a content-addressed report.', parameters: { type: 'object', required: ['manifestPath', 'artifactDir'], properties: { manifestPath: { type: 'string' }, artifactDir: { type: 'string' } }, additionalProperties: false }, execute: async args => verifyPrincipalBindingManifest({ workspaceRoot, ...args }) })
  ]
}
export function apply(ctx, config = {}) { for (const definition of createDefinitions(ctx, config)) ctx.tools.register(definition) }
