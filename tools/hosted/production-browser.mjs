// Real candidate populations and separately scoped component capacity evidence.
import { chromium, errors as playwrightErrors } from 'playwright'
import { readFile, writeFile, mkdir, readdir } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import { gzipSync } from 'node:zlib'
import { isIP } from 'node:net'
import { cpus, totalmem } from 'node:os'
import { spawnSync } from 'node:child_process'
import { graphVisibleNodeCount } from './performance-gates.mjs'
import { auditAccessibility } from './browser-accessibility.mjs'
import { BrowserContractFailure, browserDiagnostics } from './browser-failures.mjs'
import { previewBrowserPlan } from './preview-browser-plan.mjs'
import { visitOwner as owner, submitLookup, waitForAtlasView } from './production-interactions.mjs'
import { parseInput } from '../../web/app/lib/query.ts'

const diagnostics=browserDiagnostics(playwrightErrors.TimeoutError)
// One guarded boundary for setup and report errors outside the measured loops.
try {
const root = new URL('../../', import.meta.url)
diagnostics.mark('preview-origin')
const base = new URL(process.env.ATLAS_PREVIEW_URL ?? '')
if (base.protocol !== 'https:' || !/^[0-9a-f]{8,64}\.[a-z0-9][a-z0-9-]*\.pages\.dev$/.test(base.host) || base.username || base.password || base.pathname !== '/' || base.search || base.hash)
  throw new BrowserContractFailure('Production browser acceptance requires an immutable HTTPS Pages preview origin')
const plan = previewBrowserPlan(process.env)
const reportPath = new URL(plan.identity ? 'reports/production-browser-part.json' : 'reports/production-browser.json', root)
diagnostics.mark('candidate-report')
const candidate = JSON.parse(await readFile(new URL('reports/static-candidate.json', root), 'utf8'))
if (candidate.mode !== 'production' || candidate.status !== 'passed' || !/^[a-f0-9]{64}$/.test(candidate.qualification_receipt_sha256 ?? ''))
  throw new BrowserContractFailure('A qualified frozen production candidate is required')
diagnostics.mark('corpus')
const corpusBytes = await readFile(process.env.ATLAS_PRODUCTION_CORPUS ?? '.atlas-private/production-browser-corpus.json')
const corpus = JSON.parse(corpusBytes)
const validQuery = q => { try { return typeof q === 'string' && parseInput(q).canonical === q } catch { return false } }
const strata = ['ipv4_exact', 'ipv4_lpm', 'ipv6_exact', 'ipv6_lpm', 'moas', 'sparse_asn', 'dense_asn', 'inherited', 'unknown']
const keys = (value, expected) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join() === [...expected].sort().join()
function ipv4Population(corpus) {
  const proof=corpus.ipv4_network_coverage, unknown=corpus.unknown_queries?.ipv4
  if(proof===null)return validQuery(unknown)&&isIP(unknown)===4
  return unknown===null&&keys(proof,['covered_addresses','network_objects','router_intervals','lookup','class_c'])&&
    proof.covered_addresses===2**32&&Number.isSafeInteger(proof.network_objects)&&proof.network_objects>=1&&proof.network_objects<18500&&
    Number.isSafeInteger(proof.router_intervals)&&proof.router_intervals>=proof.network_objects&&proof.router_intervals<=2**32&&
    proof.lookup?.kind==='ip'&&proof.lookup.q==='0.0.0.0'&&proof.lookup.releaseId===candidate.release_id&&proof.lookup.synthetic===false&&
    typeof proof.lookup.network?.prefix==='string'&&(proof.class_c===null||proof.class_c?.prefix==='0.0.0.0/24'&&proof.class_c.cells?.length===256)
}
if (!keys(corpus,['format_version','graph_query','interaction_query','map_query','mode','queries','release_id','availability','unknown_queries','ipv4_network_coverage']) || corpus.format_version !== 3 || corpus.mode !== 'production' || corpus.release_id !== candidate.release_id ||
    !Array.isArray(corpus.queries) || corpus.queries.length !== 10000 || !validQuery(corpus.interaction_query) || isIP(corpus.interaction_query) !== 4 ||
    !(corpus.map_query === null || validQuery(corpus.map_query) && isIP(corpus.map_query) === 4 && corpus.map_query === corpus.interaction_query) ||
    !(corpus.graph_query === null || validQuery(corpus.graph_query) && corpus.graph_query.startsWith('AS')) ||
    !keys(corpus.unknown_queries,['ipv4','ipv6','asn']) || !ipv4Population(corpus) || !validQuery(corpus.unknown_queries.ipv6) || isIP(corpus.unknown_queries.ipv6) !== 6 || !validQuery(corpus.unknown_queries.asn) || !corpus.unknown_queries.asn.startsWith('AS') ||
    !Array.isArray(corpus.availability) || corpus.availability.length !== strata.length || new Set(corpus.availability.map(row=>row.stratum)).size !== strata.length ||
    corpus.availability.some((row,index)=>!keys(row,['stratum','status','sampled_queries']) || row.stratum !== strata[index] || !['observed','absent'].includes(row.status) || !Number.isInteger(row.sampled_queries) || row.sampled_queries < 0 || row.sampled_queries > 1200 || (row.status === 'observed') !== (row.sampled_queries > 0)) ||
    corpus.queries.some(q => !keys(q,['q','stratum']) || !validQuery(q.q) || !corpus.availability.some(row=>row.stratum === q.stratum && row.status === 'observed')) ||
    corpus.availability.some(row=>row.status === 'observed' && !corpus.queries.some(q=>q.stratum === row.stratum)) ||
    corpus.availability.some(row=>new Set(corpus.queries.filter(q=>q.stratum === row.stratum).map(q=>q.q)).size > row.sampled_queries) ||
    !corpus.availability.some(row=>row.stratum !== 'unknown' && row.status === 'observed') ||
    corpus.ipv4_network_coverage && corpus.queries.some(row=>row.stratum==='unknown' && isIP(row.q)===4) ||
    Object.values(corpus.unknown_queries).filter(q=>q!==null).some(q=>!corpus.queries.some(row=>row.stratum === 'unknown' && row.q === q)))
  throw new BrowserContractFailure('A versioned 10000-query real-input stratified corpus is required')
const canonical = value => value === null || typeof value !== 'object' ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(canonical).join(',')}]` : `{${Object.keys(value).sort().map(key=>`${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex')
diagnostics.mark('graph-fixture')
const fixtureBytes = await readFile(new URL('fixtures/bin/synthetic-graph24-via3.json',root))
const fixture = JSON.parse(fixtureBytes)
if (fixture.manifest.mode !== 'synthetic' || !fixture.vectors.some(row=>row.q === 'AS424240')) throw new BrowserContractFailure('Expected independently scoped graph capacity fixture')
const fixtureFiles = new Map()
for (const object of fixture.objects) {
  const bytes = Buffer.from(object.base64,'base64')
  if (bytes.length !== object.info.bytes || sha256(bytes) !== object.info.sha256 || !fixture.manifest.objects.some(info=>canonical(info) === canonical(object.info))) throw new BrowserContractFailure('Graph fixture object integrity failed')
  fixtureFiles.set(`/_atlas/objects/${object.info.sha256}.via3`,bytes)
}
// Only the isolated fixture's clock/control envelope changes. Its checked-in
// compressed observations are never added to the frozen production candidate.
const fixtureDescriptor = {...fixture.manifest};delete fixtureDescriptor.release_id
fixtureDescriptor.valid_from = Math.floor(Date.now()/1000) - 60
fixtureDescriptor.valid_until = fixtureDescriptor.valid_from + 720 * 3600
const fixtureRelease = sha256(Buffer.from(canonical(fixtureDescriptor)))
const fixtureManifest = Buffer.from(canonical({...fixtureDescriptor,release_id:fixtureRelease}))
const fixtureManifestPath = `/_atlas/releases/${fixtureRelease}/manifest.json`
fixtureFiles.set(fixtureManifestPath,fixtureManifest)
fixtureFiles.set('/_atlas/current.json',Buffer.from(canonical({format_version:3,release_id:fixtureRelease,manifest_path:fixtureManifestPath,manifest_sha256:sha256(fixtureManifest)})))
const fixtureCredits = Buffer.from(canonical({format_version:2,mode:'synthetic',release_id:fixtureRelease,entries:[]}))
const fixtureCreditsHash = sha256(fixtureCredits),fixtureCreditsPath = `/_atlas/credits/${fixtureCreditsHash}.json`
fixtureFiles.set(fixtureCreditsPath,fixtureCredits)
fixtureFiles.set('/dataset-credits.json',Buffer.from(canonical({format_version:1,current_release_id:fixtureRelease,releases:[{release_id:fixtureRelease,credits_path:fixtureCreditsPath,credits_sha256:fixtureCreditsHash}]})))
diagnostics.mark('accessibility-setup')
const axeSource = await readFile(createRequire(import.meta.url).resolve('axe-core/axe.min.js'), 'utf8')
diagnostics.mark('worker-memory-report')
const report = { scope:'hosted-production-browser-v3',release_scope:'release-scope-v6',mode:'production',url:base.origin,
  release_id:candidate.release_id,candidate_bundle_sha256:candidate.candidate_bundle_sha256,
  qualification_receipt_sha256:candidate.qualification_receipt_sha256,
  corpus_release_id:corpus.release_id,corpus_availability:corpus.availability,
  corpus_ipv4_network_coverage: corpus.ipv4_network_coverage && Object.fromEntries(['covered_addresses','router_intervals','network_objects'].map(k=>[k,corpus.ipv4_network_coverage[k]])),
  corpus_features:{map:corpus.map_query!==null,graph:corpus.graph_query!==null},
  corpus_sha256:createHash('sha256').update(corpusBytes).digest('hex'),browser:null,head_sha:process.env.GITHUB_SHA??null,
  execution_host:{platform:process.platform,arch:process.arch,node:process.versions.node,logical_cpus:cpus().length,memory_bytes:totalmem()},
  populations:[],component_populations:[],cold_queries:[],hot_queries:[],errors:[],worker_memory_samples:[],
  worst_case_worker_memory:JSON.parse(await readFile(new URL('reports/worker-memory.json',root),'utf8')),
  protocol:{widths:[320,390,1280,1440],themes:['light','dark'],independent_contexts_per_population:30,
    mobile_dpr:2,mobile_cpu_slowdown:4,network_rtt_ms:150,network_down_bits_per_second:1600000,network_up_bits_per_second:750000,
    graph_phase_ms:10000,graph_wheel_pair:'deltaY=-50,+50',graph_population:'isolated-synthetic-component-capacity;exact-production-assets;all24completecircles-insideSVG-and-screen-each1000ms',
    real_candidate:'all-owner-routes-and-verified-unknown-states;observed-graph-population-is-reported-without-substitution',
    lab_INP:'EventTiming interactionId-grouped maximum durations; 16ms observer floor; not field INP',
    CLS:'maximum-layout-shift-session-window-through-complete-trusted-interaction-script',
    memory:'100ms-browser-process-tree-RSS-diagnostic-only; between-poll peaks and separate worst-case worker proof remain unmeasured',
    accessibility:'axe-core4.14.0 WCAG2A/AA+2.1AA on every owner route; incomplete rules require review and cannot pass',
    external_network:'same-origin-atlas-real-HTTP;third-party-requests-fail'}}
report.graph_component_fixture={scope:'isolated-synthetic-capacity',fixture_sha256:sha256(fixtureBytes),worker_sha256:report.worst_case_worker_memory.worker_sha256,candidate_bundle_sha256:report.candidate_bundle_sha256}
if (!/^[a-f0-9]{64}$/.test(report.graph_component_fixture.worker_sha256 ?? '')) throw new BrowserContractFailure('Component capacity must bind the exact measured emitted worker')

let browser,server,memoryTimer,pendingMemorySample=null,rootPid
let scenarioFailed=false
function recordError(message,classification) {
  report.errors.push(message)
  diagnostics.note(classification)
}
async function processTreeRSS() {
  if (process.platform !== 'linux') return {supported:false,reason:'Linux procfs required'}
  const rows=[]
  for (const entry of await readdir('/proc',{withFileTypes:true})) {
    if (!entry.isDirectory() || !/^[1-9][0-9]*$/.test(entry.name)) continue
    try {
      const value=await readFile(`/proc/${entry.name}/stat`,'utf8'),tail=value.slice(value.lastIndexOf(')')+2).split(' ')
      rows.push({pid:Number(entry.name),ppid:Number(tail[1])})
    } catch {} // Processes can exit between procfs observations.
  }
  const included=new Set([rootPid]);let changed=true
  while(changed){changed=false;for(const row of rows)if(included.has(row.ppid)&&!included.has(row.pid)){included.add(row.pid);changed=true}}
  let rss=0,count=0
  for(const pid of included)try{const status=await readFile(`/proc/${pid}/status`,'utf8'),match=/^VmRSS:\s+([0-9]+) kB$/m.exec(status);if(match){rss+=Number(match[1])*1024;count++}}catch{}
  return {supported:count>0,at_ms:performance.now(),rss_bytes:rss,processes:count}
}

function atlasPath(path) { return path.startsWith('/_atlas/') || path === '/dataset-credits.json' }

async function newSample(width,theme,{componentFixture=false,measureColdPayload=false}={}) {
  const mobile=width<1000
  const context=await browser.newContext({viewport:{width,height:mobile?844:900},deviceScaleFactor:mobile?2:1,colorScheme:theme,reducedMotion:'no-preference',serviceWorkers:'block'})
  await context.route('**/*',route=>{
    const url=new URL(route.request().url())
    if(url.origin===base.origin)return route.continue()
    recordError('Unexpected external request origin','unexpected-request');return route.abort('blockedbyclient')
  })
  await context.addInitScript(({theme})=>{
    localStorage.setItem('nuxt-color-mode',theme)
    const NativeWorker=window.Worker
    window.__atlasWorkers=[];window.__atlasWorkerURLs=[]
    window.Worker=class extends NativeWorker{constructor(...args){super(...args);window.__atlasWorkers.push(this);window.__atlasWorkerURLs.push(String(args[0]));this.addEventListener('message',event=>{const a=event.data.answer;if(a?.q&&a?.releaseId)window.__atlasLastLookup={q:a.q,releaseId:a.releaseId,synthetic:a.synthetic}})}}
    const state=window.__atlasProduction={lcp_ms:null,cls:0,interactions:{},trusted_inputs:0,event_supported:PerformanceObserver.supportedEntryTypes.includes('event'),lcp_supported:PerformanceObserver.supportedEntryTypes.includes('largest-contentful-paint'),cls_supported:PerformanceObserver.supportedEntryTypes.includes('layout-shift')}
    for(const event of ['keydown','pointerdown','wheel'])addEventListener(event,e=>{if(e.isTrusted)state.trusted_inputs++},{capture:true,passive:true})
    if(state.lcp_supported)new PerformanceObserver(list=>{for(const e of list.getEntries())state.lcp_ms=e.startTime}).observe({type:'largest-contentful-paint',buffered:true})
    let first=0,last=0,session=0
    if(state.cls_supported)new PerformanceObserver(list=>{for(const e of list.getEntries()){if(e.hadRecentInput)continue;if(e.startTime-last>1000||e.startTime-first>5000){first=e.startTime;session=0}last=e.startTime;session+=e.value;state.cls=Math.max(state.cls,session)}}).observe({type:'layout-shift',buffered:true})
    if(state.event_supported)new PerformanceObserver(list=>{for(const e of list.getEntries())if(e.interactionId)state.interactions[e.interactionId]=Math.max(state.interactions[e.interactionId]??0,e.duration)}).observe({type:'event',buffered:true,durationThreshold:16})
  },{theme})
  const page=await context.newPage(),cdp=await context.newCDPSession(page)
  page.on('pageerror',()=>recordError('Browser page exception','page-exception'))
  await cdp.send('Network.enable');await cdp.send('Network.setCacheDisabled',{cacheDisabled:true})
  await cdp.send('Emulation.setCPUThrottlingRate',{rate:mobile?4:1})
  await cdp.send('Network.emulateNetworkConditions',{offline:false,latency:150,downloadThroughput:1600000/8,uploadThroughput:750000/8,connectionType:'cellular3g'})
  const js=new Map(),jsHashes=new Map(),atlas=[],pending=[]
  const unfinished=new Set()
  let coldRequests=0
  if(measureColdPayload){
    context.on('request',request=>{
      const url=new URL(request.url())
      if(url.origin===base.origin && atlasPath(url.pathname)){unfinished.add(request);coldRequests++}
    })
    context.on('requestfinished',request=>unfinished.delete(request))
  }
  context.on('response',response=>{
    const url=new URL(response.url());if(url.origin!==base.origin||(!/\.(?:m?js)$/.test(url.pathname)&&!atlasPath(url.pathname)))return
    pending.push((async()=>{
      if(response.status()!==200)throw new BrowserContractFailure('Static asset unavailable')
      if(/\.(?:m?js)$/.test(url.pathname)){
        const bytes=await response.body()
        js.set(url.pathname,gzipSync(bytes,{level:9}).length)
        jsHashes.set(url.pathname,sha256(bytes))
      }else if(!componentFixture){
        const sizes=await response.request().sizes()
        if(!Number.isFinite(sizes.responseBodySize)||sizes.responseBodySize<=0)throw new BrowserContractFailure('Wire bytes unavailable')
        atlas.push({path:url.pathname,body_bytes:sizes.responseBodySize})
      }
    })().catch(()=>recordError('Static response accounting failed','asset-accounting')))
  })
  const settle=async()=>{
    await page.waitForLoadState('networkidle')
    await Promise.all(pending)
    // Playwright can use Content-Length for an interrupted response. Require
    // Chrome's successful transfer completion for every cold atlas request.
    if(measureColdPayload && (unfinished.size || coldRequests!==atlas.length))throw new BrowserContractFailure('Incomplete cold atlas transfer')
  }
  return {context,page,cdp,js,jsHashes,atlas,settle}
}

async function credits(s) {
  const requests=[]
  const record=request=>{const url=new URL(request.url());if(url.pathname==='/dataset-credits.json'||url.pathname.startsWith('/_atlas/credits/')||url.pathname.startsWith('/_atlas/legal/')){if(url.origin!==base.origin||url.search||url.hash||request.headers().referer)recordError('Credit request disclosed lookup association','privacy-contract');requests.push(url.pathname)}}
  s.page.on('request',record)
  try {
    if(await s.page.getByTestId('dataset-credits').count()!==1)throw new BrowserContractFailure('Dataset credits are not global and unique')
    await s.page.getByTestId('dataset-credits').locator('summary').click()
    const index=await(await s.context.request.get(new URL('/dataset-credits.json',base).href)).json()
    const entry=index.releases.find(x=>x.release_id===candidate.release_id)
    if(!entry||index.current_release_id!==candidate.release_id)throw new BrowserContractFailure('Credit index release mismatch')
    const response=await s.context.request.get(new URL(entry.credits_path,base).href),bytes=await response.body()
    if(createHash('sha256').update(bytes).digest('hex')!==entry.credits_sha256)throw new BrowserContractFailure('Credit hash mismatch')
    const document=JSON.parse(bytes)
    if(document.format_version!==2||document.mode!=='production'||document.release_id!==candidate.release_id)throw new BrowserContractFailure('Credits claim another release, schema or mode')
    await s.page.getByTestId('dataset-credits').locator('.credits-content').filter({hasNotText:'Loading credits'}).waitFor()
    if(document.entries.length)await s.page.getByTestId('dataset-credit').first().waitFor()
    else await s.page.getByText('No dataset attribution is required for this release.',{exact:true}).waitFor()
    const rendered=await s.page.getByTestId('dataset-credit').evaluateAll(nodes=>nodes.map(node=>({name:node.querySelector('a').textContent,text:node.querySelector('p').textContent,url:node.querySelector('a').getAttribute('href'),links:[...node.querySelectorAll('a')].map(a=>({rel:a.rel,policy:a.referrerPolicy}))})))
    if(rendered.length!==document.entries.length)throw new BrowserContractFailure('Credit display population differs')
    for(let i=0;i<rendered.length;i++)if(['name','text','url'].some(k=>rendered[i][k]!==document.entries[i][k])||rendered[i].links.some(a=>!a.rel.includes('noopener')||!a.rel.includes('noreferrer')||a.policy!=='no-referrer'))throw new BrowserContractFailure('Credit notice/link differs from reviewed bytes')
    const logos=[...new Map(document.entries.filter(entry=>entry.logo).map(entry=>[entry.logo.path,entry.logo])).values()]
    for(const logo of logos){const bytes=await(await s.context.request.get(new URL(logo.path,base).href)).body();if(createHash('sha256').update(bytes).digest('hex')!==logo.sha256)throw new BrowserContractFailure('Required logo differs from reviewed bytes')}
    const images=s.page.getByTestId('visible-dataset-credits').locator('img')
    if(await images.count()!==document.entries.filter(entry=>entry.logo).length||!await images.evaluateAll(nodes=>nodes.every(node=>node.complete&&node.naturalWidth>0)))throw new BrowserContractFailure('Required dataset logo was not decoded and displayed')
    if(requests.length!==2+logos.length)throw new BrowserContractFailure('Credits did not use exactly the global legal assets')
    await s.page.getByTestId('dataset-credits').locator('summary').click()
    return {entries:document.entries.length,same_origin_requests:requests.length,query_associations:0}
  }finally{s.page.off('request',record)}
}

async function population(page) {
  const value=await page.locator('.bgp-graph svg').evaluate(svg=>{
    const box=e=>{const b=e.getBoundingClientRect();return {left:b.left,top:b.top,right:b.right,bottom:b.bottom}}
    const a=box(svg),v=box(svg.closest('.graph-viewport'))
    return {svg_bounds:a,visible_bounds:{left:Math.max(0,a.left,v.left),right:Math.min(innerWidth,a.right,v.right),top:Math.max(0,a.top,v.top),bottom:Math.min(innerHeight,a.bottom,v.bottom)},circles:[...svg.querySelectorAll('.graph-node circle')].map(box)}
  })
  value.fully_visible_nodes=graphVisibleNodeCount(value)
  if(value.circles.length!==24||value.fully_visible_nodes!==24)throw new BrowserContractFailure('The isolated capacity graph does not paint all24 complete circles')
  return value
}
async function graphPhase(page,name,action) {
  const population_checkpoints=[{checkpoint:'before',...await population(page)}]
  await page.evaluate(()=>{const s=window.__productionFrames={start:performance.now(),times:[],stop:false};const tick=t=>{if(s.stop)return;s.times.push(t);requestAnimationFrame(tick)};requestAnimationFrame(tick)})
  const start=performance.now();let actions=0,next=1000
  while(performance.now()-start<10000){await action(actions++);await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(resolve)));if(performance.now()-start>=next){population_checkpoints.push({checkpoint:'during',elapsed_ms:performance.now()-start,...await population(page)});next+=1000}}
  const result=await page.evaluate(()=>{const s=window.__productionFrames;s.stop=true;return {...s,end:performance.now()}})
  population_checkpoints.push({checkpoint:'after',...await population(page)})
  const duration_ms=result.end-result.start,complete_second_fps=Array.from({length:Math.floor(duration_ms/1000)},(_,i)=>result.times.filter(t=>t>=result.start+i*1000&&t<result.start+(i+1)*1000).length)
  return {action:name,actions,duration_ms,complete_second_fps,frame_intervals_ms:result.times.slice(1).map((t,i)=>t-result.times[i]),population_checkpoints}
}
async function accessible(page) {
  return auditAccessibility(page,axeSource)
}
async function submit(page,q,{synthetic=false}={}) {
  await submitLookup(page,q,{synthetic,releaseId:synthetic?fixtureRelease:candidate.release_id})
}
async function workerAnswer(page,action,q) {
  return page.evaluate(({action,q})=>new Promise((resolve,reject)=>{
    const worker=window.__atlasWorkers[0];if(!worker)return reject(new Error('No actual atlas worker'))
    const id=window.__atlasProbeId=(window.__atlasProbeId??0)-1
    const timer=setTimeout(()=>{worker.removeEventListener('message',receive);reject(new Error('Corpus query timeout'))},30000)
    const receive=event=>{if(event.data.id!==id)return;clearTimeout(timer);worker.removeEventListener('message',receive);event.data.error?reject(new Error('Corpus query rejected')):resolve(event.data.answer)}
    worker.addEventListener('message',receive);worker.postMessage({action,id,q})
  }),{action,q})
}
async function noFacts(page,q,synthetic=false) {
  const answer=await workerAnswer(page,'lookup',q)
  const origins=isIP(q)?[]:[Number(q.slice(2))]
  if(answer.releaseId!==(synthetic?fixtureRelease:candidate.release_id)||answer.synthetic!==synthetic||answer.geo!==null||answer.network!==null||answer.usage!==null||answer.observedRisk!==null||answer.asns.length||['paths','relationships','tier1'].some(key=>answer.bgp[key].length)||answer.bgp.rpki.some(row=>row.status!=='unavailable')||JSON.stringify(answer.bgp.origins)!==JSON.stringify(origins))throw new BrowserContractFailure('Unknown corpus query manufactured facts')
}
const overviewLabels = ['Country', 'Registration country', 'Matched prefix', 'Usage']
async function overviewFacts(page) {
  await page.locator('.fact-list').waitFor()
  const rows = await page.locator('.fact-list > div').evaluateAll(nodes =>
    nodes.map(node => [node.querySelector('dt').textContent.trim(), node.querySelector('dd').textContent.trim()]))
  if (rows.length !== overviewLabels.length || rows.some(([label], index) => label !== overviewLabels[index]))
    throw new BrowserContractFailure('Overview displayed unexpected fact labels')
  if (await page.locator('.map-panel,.map-empty,.geo-map,.leaflet-container').count())
    throw new BrowserContractFailure('Overview displayed a retired map')
  return Object.fromEntries(rows)
}
async function unknownIPv4(page,q,synthetic=false) {
  await submit(page,q,{synthetic});await noFacts(page,q,synthetic)
  if (Object.values(await overviewFacts(page)).some(value => value !== 'Unknown'))
    throw new BrowserContractFailure('Unknown IPv4 displayed identity')
  await owner(page,'Observed risk','.quality-layout',{synthetic});await page.getByRole('heading',{name:'Unrated',exact:true}).waitFor()
  if(await page.locator('.reason-chip').count()||(await page.locator('.score-value').innerText()).trim()!=='—')throw new BrowserContractFailure('Unknown IPv4 displayed scored evidence')
  await owner(page,'Class C','.ip-grid',{synthetic})
  const target=page.getByRole('gridcell',{name:`${q}, unknown`,exact:true})
  if(await page.getByRole('gridcell').count()!==256||await target.count()!==1||await target.evaluate(node=>node.classList.contains('observed')||node.classList.contains('positive')))throw new BrowserContractFailure('Unknown IPv4 cell was treated as observed')
  await owner(page,'ASN','.asn-list,.status-panel:not([role])',{synthetic});await page.getByText('No origin is evidenced for this query.',{exact:true}).waitFor()
  if(await page.locator('.asn-card').count())throw new BrowserContractFailure('Unknown IPv4 displayed an ASN')
  await owner(page,'BGP','.bgp-controls',{synthetic});await page.getByRole('heading',{name:'No observed origin',exact:true}).waitFor()
  if(await page.locator('.graph-node,.graph-edge').count())throw new BrowserContractFailure('Unknown IPv4 invented routing')
}
async function coveredIPv4(page,proof) {
  const expected=proof.lookup, q=expected.q
  await submit(page,q)
  if(canonical(await workerAnswer(page,'lookup',q))!==canonical(expected))throw new BrowserContractFailure('IPv4 coverage witness differs between the native and browser readers')
  const facts={'Country':expected.geo?.country,'Registration country':expected.geo?.registrationCountry,
    'Matched prefix':expected.network?.prefix,'Usage':expected.usage?.type}
  const visible=await overviewFacts(page)
  if(canonical(visible)!==canonical(Object.fromEntries(Object.entries(facts).map(([k,v])=>[k,v??'Unknown']))))throw new BrowserContractFailure('IPv4 coverage witness overview differs from its native facts')
  await owner(page,'Observed risk','.quality-layout')
  if(expected.observedRisk?.score==null){await page.getByRole('heading',{name:'Unrated',exact:true}).waitFor();if((await page.locator('.score-value').innerText()).trim()!=='—')throw new BrowserContractFailure('IPv4 witness acquired an unknown score')}
  await owner(page,'Class C','.ip-grid')
  if(canonical(await workerAnswer(page,'classC',q))!==canonical(proof.class_c))throw new BrowserContractFailure('IPv4 coverage witness Class C answer differs between readers')
  const grid=await page.getByRole('gridcell').evaluateAll(cells=>cells.map(cell=>[cell.getAttribute('aria-label'),cell.classList.contains('observed'),cell.classList.contains('positive')]))
  const expectedGrid=Array.from({length:256},(_,i)=>{
    const cell=proof.class_c?.cells[i],observed=cell?.observed??false,ip=cell?.ip??`0.0.0.${i}`
    return [`${ip}, ${observed?'observed':'unknown'}`,observed,Boolean(cell?.reasons.length)]
  })
  if(canonical(grid)!==canonical(expectedGrid))throw new BrowserContractFailure('IPv4 witness grid displayed different observed evidence')
  await owner(page,'ASN','.asn-list,.status-panel:not([role])')
  if(!expected.asns.length)await page.getByText('No origin is evidenced for this query.',{exact:true}).waitFor()
  const asns=await page.locator('.asn-card .eyebrow').allTextContents()
  if(canonical(asns)!==canonical(expected.asns.map(a=>`AS${a.asn}`)))throw new BrowserContractFailure('IPv4 witness displayed different ASNs')
  await owner(page,'BGP','.bgp-controls')
  const origins=await page.getByRole('combobox',{name:'Select announcing origin'}).locator('option').evaluateAll(rows=>rows.map(o=>Number(o.value)))
  if(canonical(origins)!==canonical(expected.bgp.origins))throw new BrowserContractFailure('IPv4 witness displayed different origins')
  if(!origins.length)await page.getByRole('heading',{name:'No observed origin',exact:true}).waitFor()
}
async function unknownStates(page) {
  if(corpus.unknown_queries.ipv4!==null)await unknownIPv4(page,corpus.unknown_queries.ipv4)
  else await coveredIPv4(page,corpus.ipv4_network_coverage)
  await submit(page,corpus.unknown_queries.ipv6);await overviewFacts(page);await noFacts(page,corpus.unknown_queries.ipv6)
  await owner(page,'Class C','.status-panel:not([role])');await page.getByRole('heading',{name:'IPv4 only',exact:true}).waitFor()
  if(await page.getByRole('gridcell').count())throw new BrowserContractFailure('Unknown IPv6 acquired a /24')
  await submit(page,corpus.unknown_queries.asn);await noFacts(page,corpus.unknown_queries.asn);await page.getByText('No origin is evidenced for this query.',{exact:true}).waitFor()
  if(await page.locator('.asn-card').count())throw new BrowserContractFailure('Unknown ASN displayed aggregate facts')
  await owner(page,'BGP','.bgp-graph svg');await page.getByText('No observed path is available',{exact:true}).waitFor()
  if(await page.locator('.graph-node,.graph-edge,.graph-original').count())throw new BrowserContractFailure('Unknown ASN invented a path')
  return {ipv4:corpus.unknown_queries.ipv4!==null?true:null,ipv6:true,asn:true}
}
async function actualGraph(page) {
  await submit(page,corpus.graph_query??corpus.unknown_queries.asn)
  await owner(page,'BGP','.bgp-graph svg')
  const original=page.locator('.graph-original');let observed_routes=0
  if(await original.count()){
    await original.locator('summary').click()
    const routes=original.locator('li')
    await routes.first().waitFor()
    observed_routes=await routes.count()
    await original.locator('summary').click()
  }
  const visible_nodes=await page.locator('.graph-node').count()
  if(corpus.graph_query!==null){if(!observed_routes)throw new BrowserContractFailure('Observed graph corpus lost its actual paths');return {state:'observed',visible_nodes,observed_routes,empty_state_verified:false}}
  await page.getByText('No observed path is available',{exact:true}).waitFor()
  if(visible_nodes||observed_routes||await page.locator('.graph-edge').count())throw new BrowserContractFailure('Unavailable routing displayed observations')
  return {state:'unavailable',visible_nodes,observed_routes,empty_state_verified:true}
}
async function componentPopulation(width,theme,index) {
  diagnostics.mark('component-context',index)
  const s=await newSample(width,theme,{componentFixture:true}),row={width,theme,sample:index}
  try {
    diagnostics.mark('component-fixture',index)
    await s.context.route(url=>url.origin===base.origin&&(url.pathname.startsWith('/_atlas/')||url.pathname==='/dataset-credits.json'),route=>{
      const url=new URL(route.request().url()),bytes=fixtureFiles.get(url.pathname)
      if(!bytes||url.search||url.hash){recordError('Unexpected graph fixture data request','unexpected-request');return route.abort('blockedbyclient')}
      return route.fulfill({status:200,contentType:url.pathname.endsWith('.json')?'application/json':'application/octet-stream',headers:{'content-length':String(bytes.length)},body:bytes})
    })
    await s.page.goto(new URL('/ip/',base).href,{waitUntil:'networkidle'});await s.page.getByRole('textbox').waitFor();await submit(s.page,'AS424240',{synthetic:true})
    await s.page.getByRole('navigation',{name:'Atlas views'}).getByRole('link',{name:'BGP',exact:true}).click()
    await s.page.locator('.bgp-graph svg').waitFor();await s.page.locator('.demo-label').waitFor();await s.settle()
    diagnostics.mark('component-worker',index)
    const workerURLs=await s.page.evaluate(()=>window.__atlasWorkerURLs)
    const workerHashes=[...new Set(workerURLs.map(url=>s.jsHashes.get(new URL(url,base).pathname)))]
    if(workerHashes.length!==1||workerHashes[0]!==report.graph_component_fixture.worker_sha256)throw new BrowserContractFailure('Graph capacity used a different emitted worker')
    row.worker_sha256=workerHashes[0]
    const svg=s.page.locator('.bgp-graph svg'),focus=s.page.getByRole('combobox',{name:'Focus observed route'}),count=await focus.locator('option').count()
    if(count<2||await s.page.locator('.graph-node').count()!==24)throw new BrowserContractFailure('Graph capacity fixture must paint24 nodes and selectable routes')
    const layout=await s.page.locator('.graph-node').evaluateAll(nodes=>nodes.map(node=>node.getAttribute('transform')))
    const fit=async()=>{await s.page.getByRole('button',{name:'Fit',exact:true}).click();await svg.scrollIntoViewIfNeeded();await svg.focus();await population(s.page)}
    diagnostics.mark('component-keyboard-pan',index)
    await fit();const phases=[await graphPhase(s.page,'keyboard-pan',i=>s.page.keyboard.press(i%2?'ArrowLeft':'ArrowRight'))]
    diagnostics.mark('component-wheel-zoom',index)
    await fit();const bounds=await svg.boundingBox();await s.page.mouse.move(bounds.x+bounds.width/2,bounds.y+bounds.height/2);phases.push(await graphPhase(s.page,'wheel-zoom',i=>s.page.mouse.wheel(0,i%2?50:-50)))
    diagnostics.mark('component-route-focus',index)
    await fit();await focus.focus();await focus.selectOption('-1');phases.push(await graphPhase(s.page,'route-focus',i=>s.page.keyboard.press(i%(2*(count-1))<count-1?'ArrowDown':'ArrowUp')))
    if(JSON.stringify(layout)!==JSON.stringify(await s.page.locator('.graph-node').evaluateAll(nodes=>nodes.map(node=>node.getAttribute('transform')))))throw new BrowserContractFailure('Capacity route focus reconstructed layout')
    diagnostics.mark('component-accessibility',index)
    row.graph={visible_nodes:24,active_frames:phases};row.accessibility=await accessible(s.page)
    if(row.accessibility.violations.length||row.accessibility.incomplete.length)throw new BrowserContractFailure('Graph capacity accessibility incomplete')
    diagnostics.mark('component-unknown-ipv4',index)
    await unknownIPv4(s.page,'8.8.8.8',true)
    row.ipv4_unknown_state_verified=true
    await s.settle()
  } finally {report.component_populations.push(row);await s.context.close()}
}

async function measureQueries() {
  diagnostics.mark('cold-queries')
  const ipQueries=corpus.queries.filter(query=>isIP(query.q))
  if(ipQueries.length<100)throw new BrowserContractFailure('Cold payload corpus needs at least100 real IP queries')
  for(let index=0;index<100;index++){
    const s=await newSample(390,'light',{measureColdPayload:true}),query=ipQueries[Math.floor(index*ipQueries.length/100)]
    try{await s.page.goto(new URL(`/ip/overview/?q=${encodeURIComponent(query.q)}`,base).href,{waitUntil:'networkidle'});await s.page.getByRole('heading',{name:'Overview',exact:true}).waitFor();await waitForAtlasView(s.page);await overviewFacts(s.page);if(await s.page.getByRole('alert').count())throw new BrowserContractFailure('Cold lookup failed');await s.settle();if(s.atlas.length<2)throw new BrowserContractFailure('Cold lookup did not fetch required controls');report.cold_queries.push({sample:index+1,stratum:query.stratum,atlas_body_bytes:s.atlas.reduce((sum,x)=>sum+x.body_bytes,0),responses:s.atlas})}finally{await s.context.close()}
  }
  diagnostics.mark('hot-queries')
  for(let index=1;index<=3;index++){
    const s=await newSample(1280,'light')
    try{
      await s.page.goto(new URL(`/ip/overview/?q=${encodeURIComponent(corpus.interaction_query)}`,base).href,{waitUntil:'networkidle'});await overviewFacts(s.page)
      const result=await s.page.evaluate(async queries=>{const worker=window.__atlasWorkers[0];if(!worker)throw new Error('No actual atlas worker');let id=-1;const lookup=q=>new Promise((resolve,reject)=>{const current=id--;const timeout=setTimeout(()=>{worker.removeEventListener('message',receive);reject(new Error('Worker timing timeout'))},30000);const receive=e=>{if(e.data.id!==current)return;clearTimeout(timeout);worker.removeEventListener('message',receive);if(e.data.error)reject(new Error('Worker lookup failed'));else resolve(e.data.answer)};worker.addEventListener('message',receive);worker.postMessage({action:'lookup',id:current,q})});for(const query of queries)await lookup(query);const samples=[];for(const query of queries){const start=performance.now();await lookup(query);samples.push(performance.now()-start)}return {samples_ms:samples,warmups:queries.length}},corpus.queries.slice(0,1000).map(q=>q.q))
      report.hot_queries.push({context:index,timing:'actual-worker-indexed-lookups',...result})
    }finally{await s.context.close()}
  }
}

try {
  diagnostics.mark('browser-launch')
  server=await chromium.launchServer({channel:'chrome',headless:true})
  rootPid=server.process().pid;browser=await chromium.connect(server.wsEndpoint());report.browser=browser.version()
  memoryTimer=setInterval(()=>{
    if(pendingMemorySample)return
    pendingMemorySample=processTreeRSS().then(sample=>report.worker_memory_samples.push(sample))
      .catch(()=>recordError('Browser RSS observation failed','resource-observation')).finally(()=>{pendingMemorySample=null})
  },100)
  for(const {width,theme} of plan.populations)for(let index=1;index<=30;index++){
    diagnostics.mark('ui-context',index)
    const s=await newSample(width,theme),checks=[],row={width,theme,sample:index}
    try {
      diagnostics.mark('hero',index)
      await s.page.goto(new URL('/ip/',base).href,{waitUntil:'networkidle'});await s.page.getByRole('textbox',{name:'IP address or ASN'}).waitFor();await s.settle()
      await s.page.waitForFunction(theme=>document.documentElement.classList.contains(theme),theme)
      row.lcp_ms=await s.page.evaluate(()=>window.__atlasProduction.lcp_ms);row.initial_js_gzip_bytes=[...s.js.values()].reduce((a,b)=>a+b,0)
      if(s.atlas.length)throw new BrowserContractFailure('Hero requested atlas data before an explicit action')
      checks.push(await accessible(s.page))
      diagnostics.mark('root-redirect',index)
      const redirect=await s.context.request.get(new URL('/',base).href,{maxRedirects:0});if(redirect.status()!==302||redirect.headers().location!=='/ip')throw new BrowserContractFailure('Actual root HTTP302 missing')
      diagnostics.mark('dataset-credits',index)
      row.dataset_credits=await credits(s)
      diagnostics.mark('overview',index)
      await submit(s.page,corpus.interaction_query);await overviewFacts(s.page)
      // Keep the qualified location population in the corpus independently of presentation.
      row.map={state:'not_displayed',hidden_verified:true}
      checks.push(await accessible(s.page))
      diagnostics.mark('quality',index)
      await owner(s.page,'Observed risk','.quality-layout,.unrated-panel,.quality-panel');checks.push(await accessible(s.page))
      diagnostics.mark('class-c',index)
      await owner(s.page,'Class C','.ip-grid');const cell=s.page.getByRole('gridcell').first();await cell.focus();await s.page.keyboard.press('ArrowRight');if(await s.page.getByRole('gridcell').nth(1).getAttribute('tabindex')!=='0')throw new BrowserContractFailure('Class C keyboard selection failed');checks.push(await accessible(s.page))
      diagnostics.mark('asn',index)
      await owner(s.page,'ASN','.asn-list,.status-panel:not([role])');checks.push(await accessible(s.page))
      diagnostics.mark('bgp',index)
      row.graph=await actualGraph(s.page);checks.push(await accessible(s.page))
      row.completed_routes=['overview','quality','class-c','asn','bgp']
      diagnostics.mark('unknown-states',index)
      row.unknown_states=await unknownStates(s.page);row.ipv4_network_coverage_verified=corpus.ipv4_network_coverage?true:null;checks.push(await accessible(s.page));await s.settle()
      diagnostics.mark('ui-metrics',index)
      const metric=await s.page.evaluate(()=>window.__atlasProduction)
      row.interaction_cls=metric.cls_supported?metric.cls:null;row.event_timing_supported=metric.event_supported
      row.interaction_durations_ms=metric.event_supported&&metric.trusted_inputs>0?[16,...Object.values(metric.interactions)]:[]
      row.trusted_input_events=metric.trusted_inputs;row.complete_interaction_script=true
      row.accessibility={engine:checks[0].engine,version:checks[0].version,violations:checks.flatMap(x=>x.violations),incomplete:checks.flatMap(x=>x.incomplete)}
    } finally {report.populations.push(row);await s.context.close()}
    await componentPopulation(width,theme,index)
    console.log(`Production browser population ${width}/${theme} ${index}/30`)
  }
  if(plan.queries)await measureQueries()
} catch(error) {
  diagnostics.fail(error);scenarioFailed=true
  report.errors.push('production-browser-scenario-failed')
}
finally {
  diagnostics.mark('cleanup')
  clearInterval(memoryTimer)
  await pendingMemorySample
  if(browser)await browser.close();if(server)await server.close()
  report.browser_process_tree_rss_peak_bytes=report.worker_memory_samples.reduce((peak,sample)=>sample.supported?Math.max(peak,sample.rss_bytes):peak,0)
  const packet = plan.identity ? {...plan.identity,report} : report
  diagnostics.mark('report-write')
  await mkdir(new URL('reports/',root),{recursive:true});await writeFile(reportPath,JSON.stringify(packet)+'\n')
}
const validationArgs = plan.identity
  ? ['tools/hosted/preview_shards.py','--part',fileURLToPath(reportPath),'--shard',plan.identity.shard]
  : ['-c','import json,sys;from tools.release_contract.acceptance import browser_gates,require_all;g=browser_gates(json.load(open(sys.argv[1])));print(json.dumps(g,indent=2));require_all(g)',fileURLToPath(reportPath)]
diagnostics.mark('report-validation')
const validation=spawnSync('python',validationArgs,{cwd:root,stdio:'ignore'})
if(validation.status!==0&&!scenarioFailed)diagnostics.failedReport()
process.exitCode=validation.status===0?0:1
} catch(error) {
  diagnostics.fail(error)
  process.exitCode=1
}
