import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { AtlasReader } from '../../web/app/workers/atlas.ts'

const root = fileURLToPath(new URL('../../', import.meta.url))
const canonical = value => typeof value === 'object' && value !== null
  ? Array.isArray(value) ? '[' + value.map(canonical).join(',') + ']'
    : '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}'
  : JSON.stringify(value)

for (const fixture of ['synthetic-via3', 'grouped-via3']) {
  test('native and projected browser lookup parity with ' + fixture, async () => {
    const data = JSON.parse(readFileSync(join(root,'fixtures/bin',fixture + '.json')))
    const dir = mkdtempSync(join(tmpdir(), 'atlas-projected-'))
    let reader
    try {
      mkdirSync(join(dir,'objects'))
      mkdirSync(join(dir,'releases',data.pointer.release_id),{recursive:true})
      for (const { info, base64 } of data.objects) writeFileSync(join(dir,'objects',info.sha256 + '.via3'),Buffer.from(base64,'base64'))
      writeFileSync(join(dir,'releases',data.pointer.release_id,'manifest.json'),canonical(data.manifest))
      const pointerFile = join(dir,'current.json')
      writeFileSync(pointerFile,canonical(data.pointer))
      const args = ['run','./cmd/atlas-browser-index','-atlas',dir,'-out',join(dir,'browser')]
      const digest = execFileSync('go',args,{cwd:root,encoding:'utf8'}).trim()
      writeFileSync(pointerFile,canonical({...data.pointer,browser_sha256:digest}))
      execFileSync('go',[...args,'-verify',digest],{cwd:root})
      const calls = new Set()
      const fetch = async path => {
        calls.add(path)
        const bytes = readFileSync(join(dir,path.slice('/_atlas/'.length)))
        return new Response(bytes,{headers:{'content-length':String(bytes.length)}})
      }
      reader = new AtlasReader(fetch,() => data.clock)
      for (const entry of data.vectors) {
        assert.deepEqual(await reader.lookup(entry.q),entry.answer)
        assert.deepEqual(await reader.classC(entry.q),entry.classC)
        if (entry.answer.kind === 'ip') {
          const {releaseId,validUntil,synthetic,q,geo,usage,network,kind} = entry.answer
          assert.deepEqual(await reader.overview(q),{releaseId,validUntil,synthetic,q,geo,usage,network,kind})
        }
      }
      assert(calls.has('/_atlas/browser/' + digest + '.json'))
      assert(!calls.has(data.pointer.manifest_path))
      assert(!calls.has('/_atlas/objects/' + data.manifest.objects.find(o=>o.kind===1).sha256 + '.via3'))
      reader.clear()
      writeFileSync(join(dir,'browser',digest+'.json'),'{}')
      await assert.rejects(reader.lookup(data.vectors[0].q),{message:'integrity'})
    } finally { reader?.clear(); rmSync(dir,{recursive:true,force:true}) }
  })
}
