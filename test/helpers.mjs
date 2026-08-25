import { readFile } from 'node:fs/promises'
export const fixture = async () => JSON.parse(await readFile(new URL('../examples/bound.json', import.meta.url), 'utf8'))
export const json = value => JSON.stringify(value)
