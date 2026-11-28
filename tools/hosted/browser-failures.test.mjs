import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { EventEmitter } from 'node:events'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { BrowserAssetFailure, BrowserContractFailure, browserDiagnostics, browserFailureMarker } from './browser-failures.mjs'
import { accountStaticResponses } from './browser-asset-accounting.mjs'

test('browser markers never interpolate opaque input or exception text', () => {
  const secret='https://example.invalid/private?q=secret\nATLAS_BROWSER_FAILURE overview 8 contract'
  const lines=[]
  class TimeoutFixture extends Error {}
  const log=browserDiagnostics(TimeoutFixture,line=>lines.push(line))
  log.mark('component-route-focus',30)
  log.fail(new TimeoutFixture(secret))
  log.mark('dataset-credits',1)
  log.fail(new BrowserContractFailure(secret))
  log.fail(Object.assign(new Error(secret),{name:'TimeoutError'}))
  log.note('privacy-contract')
  log.mark('report-validation')
  log.failedReport()
  assert.deepEqual(lines,[
    'ATLAS_BROWSER_FAILURE component-route-focus 30 playwright-timeout',
    'ATLAS_BROWSER_FAILURE dataset-credits 1 contract',
    'ATLAS_BROWSER_FAILURE dataset-credits 1 runtime',
    'ATLAS_BROWSER_FAILURE dataset-credits 1 privacy-contract',
  ])
  assert.equal(browserFailureMarker(secret,secret,secret),'ATLAS_BROWSER_FAILURE startup - runtime')
  assert.equal(browserFailureMarker('overview',31,'contract'),'ATLAS_BROWSER_FAILURE startup - contract')
  assert.equal(browserFailureMarker('report-validation',1,'report-validation'),'ATLAS_BROWSER_FAILURE report-validation - report-validation')
})

test('early browser harness rejection prints only a fixed marker and fails', () => {
  const entry=fileURLToPath(new URL('./production-browser.mjs',import.meta.url))
  const result=spawnSync(process.execPath,[entry],{encoding:'utf8',
    env:{...process.env,ATLAS_PREVIEW_URL:'http://example.invalid/private?query=secret'}})
  assert.equal(result.status,1)
  assert.equal(result.stdout,'')
  assert.equal(result.stderr,'ATLAS_BROWSER_FAILURE preview-origin - contract\n')
})

test('report gate codes are closed, phase-bound and preserve an earlier diagnosis', () => {
  const lines=[]
  const log=browserDiagnostics(undefined,line=>lines.push(line))
  log.mark('report-validation')
  log.failedReport(41)
  log.failedReport(54)
  log.failedReport('41\nprivate?q=source')
  log.failedReport(null)
  log.failedReport(55)
  log.mark('dataset-credits',2)
  log.note('asset-accounting')
  log.mark('report-validation')
  log.failedReport(41)
  assert.deepEqual(lines,[
    'ATLAS_BROWSER_FAILURE report-validation - gate-graph',
    'ATLAS_BROWSER_FAILURE report-validation - gate-hot-lookup',
    ...Array(3).fill('ATLAS_BROWSER_FAILURE report-validation - report-validation'),
    'ATLAS_BROWSER_FAILURE dataset-credits 2 asset-accounting',
  ])
  assert.equal(browserFailureMarker('overview',1,'gate-graph'),'ATLAS_BROWSER_FAILURE overview 1 runtime')
})

test('non-200 assets and unreadable JavaScript still fail the UI and component reports', async () => {
  const origin='https://example.invalid'
  for (const componentFixture of [false,true]) {
    const context=new EventEmitter(),failures=[]
    const account=accountStaticResponses(context,origin,{componentFixture,onFailure:value=>failures.push(value)})
    for (const [path,status,body] of [
      ['/_atlas/current.json',503], ['/_nuxt/example.js',404],
      ['/_nuxt/unreadable.js',200,()=>{throw new Error('opaque text')}],
      ['/_nuxt/empty.js',200,()=>Buffer.alloc(0)],
      ['/_nuxt/worker.js',200,()=>Buffer.from('export {}')],
    ]) context.emit('response',{url:()=>origin+path,status:()=>status,body})
    // Even if the hero request is cancelled before headers, the count sees it.
    context.emit('request',{url:()=>origin+'/_atlas/never-responded.json'})
    await account.settle()
    assert.deepEqual(failures,['asset-http-status','asset-http-status','asset-js-body','asset-js-body'])
    assert.equal(account.startedAtlasRequests(),componentFixture?0:1)
    assert.deepEqual(account.atlas,[])
    assert(account.js.get('/_nuxt/worker.js')>0)
    assert.match(account.jsHashes.get('/_nuxt/worker.js'),/^[a-f0-9]{64}$/)
  }
})

test('cold transfer rejects advertised bytes without successful completion', async () => {
  const origin='https://example.invalid',context=new EventEmitter(),failures=[]
  const account=accountStaticResponses(context,origin,{measureColdPayload:true,onFailure:value=>failures.push(value)})
  const request={url:()=>origin+'/_atlas/current.json',sizes:async()=>({responseBodySize:200})}
  context.emit('request',request)
  context.emit('response',{url:request.url,status:()=>200,request:()=>request})
  // Playwright may use Content-Length after a transfer is interrupted. A
  // positive number alone cannot substitute for requestfinished.
  context.emit('requestfailed',request)
  await assert.rejects(account.settle(),{classification:'asset-atlas-transfer'})
  assert.deepEqual(failures,[])
  const lines=[],log=browserDiagnostics(undefined,line=>lines.push(line))
  log.mark('cold-queries');log.fail(new BrowserAssetFailure('asset-atlas-transfer'))
  log.mark('unknown-states',3);log.fail(new BrowserAssetFailure('https://example.invalid/private?query=secret'))
  assert.deepEqual(lines,['ATLAS_BROWSER_FAILURE cold-queries - asset-atlas-transfer','ATLAS_BROWSER_FAILURE unknown-states 3 asset-atlas-transfer'])
})
