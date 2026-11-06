# dsh-principal-binding-proof

**Maintainer / Author：He Fangsheng (贺方升 / 贺去病; Dosen) · [hequbing.com](https://www.hequbing.com)**

Offline, content-addressed evidence that one pseudonymous authority and tenant remain consistently bound across a DSH execution chain: principal → session → agent → tool call → runtime → artifact.

It validates explicit recorded hashes, revision, key epoch, evidence freshness, issuer allowlists, validity windows, revocation, adjacency and a unique acyclic chain. It detects authority swaps, cross-tenant confusion, stale identities, broken or mis-typed bindings, unauthorized issuers and terminal artifact mismatches.

## Boundary

This is not authentication, authorization, signature verification, access control or a remote transport. It grants no authority, reads no accounts, credentials, prompts or business payloads, and executes no commands.

- `dsh-decision-effect-proof` reconciles authorization decisions with effects.
- `dsh-attestation-proof` verifies signed DSSE/in-toto statements.
- `dsh-lineage` tracks object and action provenance.
- This plugin checks the narrower identity-confusion question: whether every redacted execution surface claims the same authority, tenant and revision through a valid explicit binding chain.

See [`examples/bound.json`](examples/bound.json).

```bash
npm test
npm run check
node bin/dsh-principal-binding-proof.mjs verify examples/bound.json
dsh plugin --profile proof add .
```

DSH tools are `dsh_principal_binding_inspect` and `dsh_principal_binding_verify`. MCP exposes proof-only inline equivalents. Workspace verification accepts only relative, non-symlink paths and writes a deterministic content-addressed report beneath an explicit `artifactDir`, followed by SHA-256 read-back verification.

MIT licensed. See [SECURITY.md](SECURITY.md).
