import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, isAbsolute, join, relative, resolve } from 'node:path'

type ModuleInfo = { importedIds: string[]; dynamicallyImportedIds: string[] }
type Context = { getModuleIds(): IterableIterator<string>; getModuleInfo(id: string): ModuleInfo | null }
type Asset = { type: 'asset'; fileName: string; source: string | Uint8Array }
type Chunk = { type: 'chunk'; fileName: string; code: string; modules: Record<string, { renderedLength: number }> }
type Module = { id: string; package: string | null; version: string | null; rendered_bytes: number }
type Bundle = { modules: Module[]; assets: { path: string; bytes: number; sha256: string }[] }
const digest = (value: string | Uint8Array) => createHash('sha256').update(value).digest('hex')
const slash = (value: string) => value.replaceAll('\\', '/')

export function installedPackage(id: string, workspace: string): { name: string; version: string } | null {
  const path = slash(id.split('?')[0]!)
  const offset = path.lastIndexOf('/node_modules/')
  if (offset < 0 || path.includes('\0')) return null
  const parts = path.slice(offset + '/node_modules/'.length).split('/')
  const length = parts[0]?.startsWith('@') ? 2 : 1
  if (parts.length < length || parts[0] === '.pnpm') return null
  const root = resolve(path.slice(0, offset + '/node_modules/'.length), ...parts.slice(0, length))
  const modules = resolve(workspace, 'web/node_modules')
  const scope = relative(modules, root)
  if (scope === '..' || scope.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) || isAbsolute(scope)) throw new Error('bundle module escaped installed package tree')
  const metadata = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { name?: unknown; version?: unknown }
  if (typeof metadata.name !== 'string' || typeof metadata.version !== 'string' || metadata.name !== parts.slice(0, length).join('/')) throw new Error('bundle package identity is invalid')
  return { name: metadata.name, version: metadata.version }
}

// Capture actual client and worker compiler module ancestry. Reports stay
// private; no source maps or module names are added to public output.
export function bundleLicenseAudit(workspace: string) {
  const root = resolve(workspace)
  let workers: Bundle[] = []
  const plugin = (kind: 'client' | 'worker') => {
    let skip = false
    const capture = function(this: Context, _options: unknown, output: Record<string, Asset | Chunk>) {
        if (skip) return
        const rendered = new Map<string, number>()
        const ids = new Set(this.getModuleIds())
        const assets: Bundle['assets'] = []
        for (const file of Object.values(output)) {
          if (/\.(?:m?js|css|wasm)$/.test(file.fileName)) {
            const bytes = file.type === 'chunk' ? Buffer.from(file.code) : Buffer.from(file.source)
            assets.push({ path: slash(file.fileName), bytes: bytes.length, sha256: digest(bytes) })
          }
          if (file.type === 'chunk') for (const [id, module] of Object.entries(file.modules)) { ids.add(id); rendered.set(id, (rendered.get(id) ?? 0) + module.renderedLength) }
        }
        const modules = [...ids].sort().map(id => {
          const installed = installedPackage(id, root)
          const file = id.split('?')[0]!
          const name = isAbsolute(file) ? slash(relative(root, file)) + id.slice(file.length) : id
          return { id: name, package: installed?.name ?? null, version: installed?.version ?? null, rendered_bytes: rendered.get(id) ?? 0 }
        })
        const result: Bundle = { modules, assets: assets.sort((a, b) => a.path.localeCompare(b.path, 'en')) }
        if (kind === 'worker') { workers.push(result); return }
        const hashes = new Set(assets.map(asset => asset.sha256))
        for (const worker of workers) for (const asset of worker.assets) if (!hashes.has(asset.sha256)) throw new Error('worker audit is not bound to a final client asset')
        const destination = join(root, 'build-private/software-bundle-audit.json')
        mkdirSync(dirname(destination), { recursive: true })
        writeFileSync(destination, JSON.stringify({ format_version: 1, scope: 'exact-client-and-worker-module-ancestry', client: result, workers }, null, 2) + '\n')
    }
    return {
      name: `atlas-private-software-audit-${kind}`,
      apply: 'build' as const,
      configResolved(config: { build: { ssr?: boolean | string } }) { skip = Boolean(config.build.ssr) },
      buildStart() { if (!skip && kind === 'client') workers = [] },
      // Vite modifies preload imports and CSS after user generateBundle hooks.
      // Capture main assets only once every generateBundle hook has finished.
      generateBundle: kind === 'worker' ? capture : undefined,
      writeBundle: kind === 'client' ? capture : undefined,
    }
  }
  return { client: plugin('client'), workers: () => [plugin('worker')] }
}
