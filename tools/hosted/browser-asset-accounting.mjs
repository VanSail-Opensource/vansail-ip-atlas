import { createHash } from 'node:crypto'
import { gzipSync } from 'node:zlib'
import { BrowserAssetFailure } from './browser-failures.mjs'

function atlasPath(path) { return path.startsWith('/_atlas/') || path === '/dataset-credits.json' }
const scriptPath=/\.(?:m?js)$/
const emittedWorkerPath=/^\/_nuxt\/atlas-[\w-]+\.(?:m?js)$/
const generatedJavaScriptPath=/^\/_nuxt\/[\w-]+\.(?:m?js)$/
const prefetchPurpose=headers=>[headers['sec-purpose'],headers.purpose].some(value=>
  typeof value==='string'&&value.toLowerCase().split(/[\s;,]+/).includes('prefetch'))

export function makePrefetchByteReader(origin) {
  const verifiedPrefetchedScripts=new Map()
  return async (page,path)=>{
    if(!generatedJavaScriptPath.test(path))throw new BrowserAssetFailure('asset-js-body')
    if(!verifiedPrefetchedScripts.has(path)){
      const reading=(async()=>{
        // The exact release and this immutable Pages origin are bound to the
        // whole-file verification before and after all browser populations.
        // This separate same-origin read starts only after the measured renderer
        // requests and LCP have been recorded. It cannot satisfy a worker load.
        const url=new URL(path,origin).href
        const encoded=await page.evaluate(async ({url,limit})=>{
          const response=await fetch(url,{cache:'no-store',credentials:'omit',redirect:'error',
            referrerPolicy:'no-referrer',signal:AbortSignal.timeout(10000)})
          if(response.status!==200||response.url!==url||!response.body)return null
          const chunks=[];let length=0
          for await(const chunk of response.body){
            length+=chunk.length
            if(length>=limit)return null
            chunks.push(chunk)
          }
          const bytes=new Uint8Array(length);let offset=0
          for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length}
          return bytes.toBase64()
        },{url,limit:24*1024**2})
        if(!encoded)throw new BrowserAssetFailure('asset-js-body')
        return Buffer.from(encoded,'base64')
      })()
      verifiedPrefetchedScripts.set(path,reading)
    }
    return verifiedPrefetchedScripts.get(path)
  }
}

export function accountStaticResponses(context,origin,{componentFixture=false,measureColdPayload=false,
  measureInitialJavaScript=false,readPrefetchedJavaScript,onFailure}) {
  const js=new Map(),jsHashes=new Map(),atlas=[],pending=[],unfinishedCold=new Set()
  const capturedScripts=new Map(),unfinishedScripts=new Set(),opaquePrefetches=new Set()
  let started=0, firstColdFailure, initial=measureInitialJavaScript
  const coldFailure=classification=>{firstColdFailure??=classification;onFailure(classification)}
  function recordScript(path,bytes){
    if(!bytes.length)throw new BrowserAssetFailure('asset-js-body')
    const digest=createHash('sha256').update(bytes).digest('hex'),previous=jsHashes.get(path)
    if(previous&&previous!==digest)throw new BrowserAssetFailure('asset-js-body')
    js.set(path,gzipSync(bytes,{level:9}).length)
    jsHashes.set(path,digest)
  }
  context.on('request',request=>{
    const url=new URL(request.url())
    if(url.origin!==origin)return
    if(!componentFixture&&atlasPath(url.pathname)){
      started++
      if(measureColdPayload)unfinishedCold.add(request)
    }
    if((initial&&scriptPath.test(url.pathname)||componentFixture&&emittedWorkerPath.test(url.pathname)&&
        request.resourceType()==='script')&&request.method()==='GET'){
      unfinishedScripts.add(request)
      if(componentFixture){
        // Chromium's ordinary prefetch is "other"; a speculative Request
        // must not satisfy executable worker identity even if it supplies a body.
        const required=Promise.resolve().then(()=>request.allHeaders()).then(headers=>!prefetchPurpose(headers))
          .catch(()=>{onFailure('asset-js-transfer');return false})
        capturedScripts.set(request,required)
        pending.push(required.then(value=>{if(!value)unfinishedScripts.delete(request)}))
      }else capturedScripts.set(request,true)
    }
  })
  if(measureColdPayload||measureInitialJavaScript||componentFixture)context.on('requestfinished',request=>{
    unfinishedCold.delete(request);unfinishedScripts.delete(request)
  })
  context.on('response',response=>{
    const url=new URL(response.url()),javascript=scriptPath.test(url.pathname),atlasAsset=atlasPath(url.pathname)
    if(url.origin!==origin||(!javascript&&!atlasAsset))return
    if(response.status()!==200){
      if(measureColdPayload&&atlasAsset&&!javascript)coldFailure('asset-http-status')
      else onFailure('asset-http-status')
      return
    }
    if(javascript&&capturedScripts.has(response.request())){
      pending.push((async()=>{
        if(!await capturedScripts.get(response.request()))return
        const bytes=await response.body()
        if(bytes.length){recordScript(url.pathname,bytes);return}
        const request=response.request()
        if(componentFixture||!measureInitialJavaScript||!generatedJavaScriptPath.test(url.pathname)||url.search||url.hash||
            request.resourceType()!=='other')throw new BrowserAssetFailure('asset-js-body')
        const headers=await request.allHeaders()
        if((headers['sec-purpose']??headers.purpose)!=='prefetch')throw new BrowserAssetFailure('asset-js-body')
        const sizes=await request.sizes()
        if(!Number.isFinite(sizes.responseBodySize)||sizes.responseBodySize<=0)throw new BrowserAssetFailure('asset-js-body')
        opaquePrefetches.add(url.pathname)
      })().catch(()=>onFailure('asset-js-body')))
    }else if(!javascript&&measureColdPayload){
      pending.push((async()=>{
        const sizes=await response.request().sizes()
        if(!Number.isFinite(sizes.responseBodySize)||sizes.responseBodySize<=0)throw new BrowserAssetFailure('asset-atlas-size')
        atlas.push({path:url.pathname,body_bytes:sizes.responseBodySize})
      })().catch(()=>coldFailure('asset-atlas-size')))
    }
  })
  return {js,jsHashes,atlas,startedAtlasRequests:()=>started,async settle(){
    // Only the initial page and emitted worker consume JS bodies. Chromium
    // can transfer an incidental prefetch but not expose its body to DevTools.
    // HTTP status remains checked above for every targeted response.
    initial=false
    await Promise.all(pending)
    if(unfinishedScripts.size)throw new BrowserAssetFailure('asset-js-transfer')
    // Route switches may cancel older reads in the UI. Only the cold corpus
    // consumes wire bytes and requires a successful transfer for every start.
    // Playwright can fall back to Content-Length on an interrupted response.
    if(measureColdPayload&&(unfinishedCold.size||started!==atlas.length))
      throw new BrowserAssetFailure(firstColdFailure??'asset-atlas-transfer')
  },async completeInitialJavaScript(){
    // An explicit prefetch uses the same immutable path as its executable
    // byte capture. Only opaque, successfully finished browser prefetches
    // without an executable capture need a separate read of that exact path.
    for(const path of opaquePrefetches){
      if(!js.has(path)){
        try{recordScript(path,await readPrefetchedJavaScript(path))}
        catch{onFailure('asset-js-body')}
      }
    }
    opaquePrefetches.clear()
  }}
}
