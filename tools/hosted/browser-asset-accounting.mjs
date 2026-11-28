import { createHash } from 'node:crypto'
import { gzipSync } from 'node:zlib'
import { BrowserAssetFailure } from './browser-failures.mjs'

function atlasPath(path) { return path.startsWith('/_atlas/') || path === '/dataset-credits.json' }

export function accountStaticResponses(context,origin,{componentFixture=false,measureColdPayload=false,onFailure}) {
  const js=new Map(),jsHashes=new Map(),atlas=[],pending=[],unfinished=new Set()
  let started=0, firstFailure
  const fail=classification=>{firstFailure??=classification;onFailure(classification)}
  if(!componentFixture)context.on('request',request=>{
    const url=new URL(request.url())
    if(url.origin===origin && atlasPath(url.pathname)){
      started++
      if(measureColdPayload)unfinished.add(request)
    }
  })
  if(measureColdPayload)context.on('requestfinished',request=>unfinished.delete(request))
  context.on('response',response=>{
    const url=new URL(response.url()), javascript=/\.(?:m?js)$/.test(url.pathname)
    if(url.origin!==origin||(!javascript&&!atlasPath(url.pathname)))return
    if(response.status()!==200){fail('asset-http-status');return}
    if(javascript){
      pending.push((async()=>{
        const bytes=await response.body()
        if(!bytes.length)throw new BrowserAssetFailure('asset-js-body')
        js.set(url.pathname,gzipSync(bytes,{level:9}).length)
        jsHashes.set(url.pathname,createHash('sha256').update(bytes).digest('hex'))
      })().catch(()=>fail('asset-js-body')))
    }else if(measureColdPayload){
      pending.push((async()=>{
        const sizes=await response.request().sizes()
        if(!Number.isFinite(sizes.responseBodySize)||sizes.responseBodySize<=0)throw new BrowserAssetFailure('asset-atlas-size')
        atlas.push({path:url.pathname,body_bytes:sizes.responseBodySize})
      })().catch(()=>fail('asset-atlas-size')))
    }
  })
  return {js,jsHashes,atlas,startedAtlasRequests:()=>started,async settle(){
    await Promise.all(pending)
    // Route switches may cancel older reads in the UI. Only the cold corpus
    // consumes wire bytes and requires a successful transfer for every start.
    // Playwright can fall back to Content-Length on an interrupted response.
    if(measureColdPayload&&(unfinished.size||started!==atlas.length))
      throw new BrowserAssetFailure(firstFailure??'asset-atlas-transfer')
  }}
}
