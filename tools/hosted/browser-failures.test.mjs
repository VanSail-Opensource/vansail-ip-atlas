import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { EventEmitter } from 'node:events'
import { createHash } from 'node:crypto'
import { gzipSync } from 'node:zlib'
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

const origin='https://example.invalid'
function transfer(context,path,{status=200,body=()=>Buffer.from('export {}'),method='GET',size=80,type='script',purpose,finished=true}={}){
  const request={url:()=>origin+path,method:()=>method,sizes:async()=>({responseBodySize:size}),
    resourceType:()=>type,allHeaders:async()=>purpose?{'sec-purpose':purpose}:{}}
  context.emit('request',request)
  context.emit('response',{url:request.url,status:()=>status,request:()=>request,body})
  context.emit(finished?'requestfinished':'requestfailed',request)
}

test('non-200 assets fail every cohort; unreadable bodies fail only their required consumers', async () => {
  for (const options of [{measureInitialJavaScript:true},{componentFixture:true},{measureColdPayload:true}]) {
    const context=new EventEmitter(),failures=[]
    const account=accountStaticResponses(context,origin,{...options,onFailure:value=>failures.push(value)})
    transfer(context,'/_nuxt/example.js',{status:404})
    transfer(context,'/_nuxt/atlas-unreadable.js',{body:()=>{throw new Error('opaque text')}})
    transfer(context,'/_nuxt/atlas-empty.js',{body:()=>Buffer.alloc(0)})
    transfer(context,'/_nuxt/atlas-worker.js')
    transfer(context,'/_nuxt/head-only.js',{method:'HEAD',body:()=>Buffer.alloc(0)})
    transfer(context,'/_atlas/current.json',{status:503})
    // Even if the hero request is cancelled before headers, the count sees it.
    context.emit('request',{url:()=>origin+'/_atlas/never-responded.json'})
    if(options.measureColdPayload)await assert.rejects(account.settle(),{classification:'asset-http-status'})
    else await account.settle()
    assert.deepEqual(failures,options.measureColdPayload?['asset-http-status','asset-http-status']:
      ['asset-http-status','asset-http-status','asset-js-body','asset-js-body'])
    assert.equal(account.startedAtlasRequests(),options.componentFixture?0:2)
    assert.deepEqual(account.atlas,[])
    if(options.measureColdPayload)assert.equal(account.js.size,0)
    else {
      assert(account.js.get('/_nuxt/atlas-worker.js')>0)
      assert.match(account.jsHashes.get('/_nuxt/atlas-worker.js'),/^[a-f0-9]{64}$/)
    }
  }
})

test('initial JS gzip counts opaque completed prefetches and reuses real script bodies when present', async () => {
  const context=new EventEmitter(),failures=[],reads=[],bytes=Buffer.from('const measured=1')
  const account=accountStaticResponses(context,origin,{measureInitialJavaScript:true,
    readPrefetchedJavaScript:async path=>{reads.push(path);return bytes},onFailure:value=>failures.push(value)})
  const opaque={body:()=>Buffer.alloc(0),type:'other',purpose:'prefetch'}
  transfer(context,'/_nuxt/prefetch-only.js',opaque)
  transfer(context,'/_nuxt/prefetched-and-used.js',opaque)
  transfer(context,'/_nuxt/prefetched-and-used.js',{body:()=>bytes})
  await account.settle()
  assert.deepEqual(reads,[],'Running the initial sample must not issue recovery requests')
  await account.completeInitialJavaScript()
  assert.deepEqual(reads,['/_nuxt/prefetch-only.js'])
  assert.deepEqual(failures,[])
  assert.equal([...account.js.values()].reduce((sum,x)=>sum+x,0),2*gzipSync(bytes,{level:9}).length)
  assert.equal(account.jsHashes.get('/_nuxt/prefetch-only.js'),createHash('sha256').update(bytes).digest('hex'))
  transfer(context,'/_nuxt/warm-navigation.js',{body:()=>{throw new Error()},finished:false})
  await account.settle()
  assert.deepEqual(failures,[],'Unmeasured navigation bodies and generic teardown are not byte failures')
})

test('fallback cannot replace a failed or unmeasured initial script or worker body', async () => {
  const opaque={body:()=>Buffer.alloc(0),type:'other',purpose:'prefetch'}
  for (const [options,path,metadata,expected] of [
    [{measureInitialJavaScript:true},'/_nuxt/app.js',{...opaque,type:'script'},'asset-js-body'],
    [{measureInitialJavaScript:true},'/_nuxt/app.js?q=opaque',opaque,'asset-js-body'],
    [{measureInitialJavaScript:true},'/_nuxt/app.js',{...opaque,size:0},'asset-js-body'],
    [{measureInitialJavaScript:true},'/_nuxt/app.js',{...opaque,finished:false},'asset-js-transfer'],
    [{componentFixture:true},'/_nuxt/atlas-worker.js',opaque,'asset-js-body'],
  ]) {
    const context=new EventEmitter(),failures=[],reads=[]
    const account=accountStaticResponses(context,origin,{...options,
      readPrefetchedJavaScript:async path=>{reads.push(path);return Buffer.from('must not be read')},
      onFailure:value=>failures.push(value)})
    transfer(context,path,metadata)
    if(expected==='asset-js-transfer')await assert.rejects(account.settle(),{classification:expected})
    else {await account.settle();await account.completeInitialJavaScript();assert.deepEqual(failures,[expected])}
    assert.deepEqual(reads,[])
  }
  const context=new EventEmitter(),request={url:()=>origin+'/_nuxt/app.js',method:()=>'GET'}
  const account=accountStaticResponses(context,origin,{measureInitialJavaScript:true,onFailure:()=>{}})
  context.emit('request',request);context.emit('requestfailed',request)
  await assert.rejects(account.settle(),{classification:'asset-js-transfer'})
})

test('cold transfer rejects advertised bytes without completion and keeps unrelated JS status separate', async () => {
  const context=new EventEmitter(),failures=[]
  const account=accountStaticResponses(context,origin,{measureColdPayload:true,onFailure:value=>failures.push(value)})
  transfer(context,'/_nuxt/unavailable.js',{status:502})
  transfer(context,'/_nuxt/opaque-prefetch.js',{body:()=>{throw new Error('Body is not consumed')}})
  const request={url:()=>origin+'/_atlas/current.json',sizes:async()=>({responseBodySize:200})}
  context.emit('request',request)
  context.emit('response',{url:request.url,status:()=>200,request:()=>request})
  // Playwright may use Content-Length after a transfer is interrupted. A
  // positive number alone cannot substitute for requestfinished.
  context.emit('requestfailed',request)
  await assert.rejects(account.settle(),{classification:'asset-atlas-transfer'})
  assert.deepEqual(failures,['asset-http-status'])
  const lines=[],log=browserDiagnostics(undefined,line=>lines.push(line))
  log.mark('cold-queries');log.fail(new BrowserAssetFailure('asset-atlas-transfer'))
  log.mark('unknown-states',3);log.fail(new BrowserAssetFailure('https://example.invalid/private?query=secret'))
  assert.deepEqual(lines,['ATLAS_BROWSER_FAILURE cold-queries - asset-atlas-transfer','ATLAS_BROWSER_FAILURE unknown-states 3 asset-atlas-transfer'])
})
