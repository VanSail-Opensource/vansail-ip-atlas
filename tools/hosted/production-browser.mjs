// Mandatory production populations. Never substitutes synthetic data or missing metrics.
import { chromium } from 'playwright'
import { readFile, writeFile, mkdir, readdir } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import { gzipSync } from 'node:zlib'
import { isIP } from 'node:net'
import { cpus, totalmem } from 'node:os'
import { spawnSync } from 'node:child_process'
import { graphVisibleNodeCount } from './performance-gates.mjs'

const root = new URL('../../', import.meta.url)
const base = new URL(process.env.ATLAS_PREVIEW_URL ?? '')
if (base.protocol !== 'https:' || !/^[0-9a-f]{8,64}\.[a-z0-9][a-z0-9-]*\.pages\.dev$/.test(base.host) || base.username || base.password || base.pathname !== '/' || base.search || base.hash)
  throw new Error('Production browser acceptance requires an immutable HTTPS Pages preview origin')
const reportPath = new URL('reports/production-browser.json', root)
const candidate = JSON.parse(await readFile(new URL('reports/static-candidate.json', root), 'utf8'))
if (candidate.mode !== 'production' || candidate.status !== 'passed' || !/^[a-f0-9]{64}$/.test(candidate.qualification_receipt_sha256 ?? ''))
  throw new Error('A qualified frozen production candidate is required')
const corpusBytes = await readFile(process.env.ATLAS_PRODUCTION_CORPUS ?? '.atlas-private/production-browser-corpus.json')
const corpus = JSON.parse(corpusBytes)
const validQuery = q => typeof q === 'string' && (isIP(q) !== 0 || /^AS[1-9][0-9]{0,9}$/.test(q) && Number(q.slice(2)) <= 4294967294)
const strata = ['ipv4_exact', 'ipv4_lpm', 'ipv6_exact', 'ipv6_lpm', 'moas', 'sparse_asn', 'dense_asn', 'inherited', 'unknown']
if (Object.keys(corpus).sort().join() !== ['format_version','graph_query','interaction_query','mode','queries'].sort().join() || corpus.format_version !== 1 || corpus.mode !== 'production' ||
    !Array.isArray(corpus.queries) || corpus.queries.length !== 10000 || !validQuery(corpus.interaction_query) || !isIP(corpus.interaction_query) || !validQuery(corpus.graph_query) ||
    corpus.queries.some(q => Object.keys(q).sort().join() !== 'q,stratum' || !validQuery(q.q) || !strata.includes(q.stratum)) || strata.some(s => !corpus.queries.some(q => q.stratum === s)))
  throw new Error('A versioned 10000-query real-input stratified corpus is required')
const axeSource = await readFile(createRequire(import.meta.url).resolve('axe-core/axe.min.js'), 'utf8')
const tile = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+j9zEAAAAASUVORK5CYII=', 'base64')
const report = { scope:'hosted-production-browser-v1',mode:'production',url:base.origin,
  release_id:candidate.release_id,candidate_bundle_sha256:candidate.candidate_bundle_sha256,
  corpus_sha256:createHash('sha256').update(corpusBytes).digest('hex'),browser:null,head_sha:process.env.GITHUB_SHA??null,
  execution_host:{platform:process.platform,arch:process.arch,node:process.versions.node,logical_cpus:cpus().length,memory_bytes:totalmem()},
  populations:[],cold_queries:[],hot_queries:[],errors:[],worker_memory_samples:[],
  worst_case_worker_memory:JSON.parse(await readFile(new URL('reports/worker-memory.json',root),'utf8')),
  protocol:{widths:[320,390,1280,1440],themes:['light','dark'],independent_contexts_per_population:30,
    mobile_dpr:2,mobile_cpu_slowdown:4,network_rtt_ms:150,network_down_bits_per_second:1600000,network_up_bits_per_second:750000,
    graph_phase_ms:10000,graph_wheel_pair:'deltaY=-50,+50',graph_population:'all24completecircles-insideSVG-and-screen-each1000ms',
    lab_INP:'EventTiming interactionId-grouped maximum durations; 16ms observer floor; not field INP',
    CLS:'maximum-layout-shift-session-window-through-complete-trusted-interaction-script',
    memory:'100ms-browser-process-tree-RSS-diagnostic-only; between-poll peaks and separate worst-case worker proof remain unmeasured',
    accessibility:'axe-core4.14.0 WCAG2A/AA+2.1AA on every owner route; incomplete rules require review and cannot pass',
    map_tiles:'same-origin-atlas-real-HTTP;external-OSM-tiles-mocked-and-excluded-from-atlas-payload'}}

let browser,server,memoryTimer,memoryBusy=false,rootPid
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

async function newSample(width,theme) {
  const mobile=width<1000
  const context=await browser.newContext({viewport:{width,height:mobile?844:900},deviceScaleFactor:mobile?2:1,colorScheme:theme,reducedMotion:'no-preference',serviceWorkers:'block'})
  await context.route('**/*',route=>{
    const url=new URL(route.request().url())
    if(url.origin===base.origin)return route.continue()
    if(url.origin==='https://tile.openstreetmap.org')return route.fulfill({status:200,contentType:'image/png',body:tile})
    report.errors.push('Unexpected external request origin');return route.abort('blockedbyclient')
  })
  await context.addInitScript(({theme})=>{
    localStorage.setItem('nuxt-color-mode',theme)
    const NativeWorker=window.Worker
    window.__atlasWorkers=[]
    window.Worker=class extends NativeWorker{constructor(...args){super(...args);window.__atlasWorkers.push(this)}}
    const state=window.__atlasProduction={lcp_ms:null,cls:0,interactions:{},trusted_inputs:0,event_supported:PerformanceObserver.supportedEntryTypes.includes('event'),lcp_supported:PerformanceObserver.supportedEntryTypes.includes('largest-contentful-paint'),cls_supported:PerformanceObserver.supportedEntryTypes.includes('layout-shift')}
    for(const event of ['keydown','pointerdown','wheel'])addEventListener(event,e=>{if(e.isTrusted)state.trusted_inputs++},{capture:true,passive:true})
    if(state.lcp_supported)new PerformanceObserver(list=>{for(const e of list.getEntries())state.lcp_ms=e.startTime}).observe({type:'largest-contentful-paint',buffered:true})
    let first=0,last=0,session=0
    if(state.cls_supported)new PerformanceObserver(list=>{for(const e of list.getEntries()){if(e.hadRecentInput)continue;if(e.startTime-last>1000||e.startTime-first>5000){first=e.startTime;session=0}last=e.startTime;session+=e.value;state.cls=Math.max(state.cls,session)}}).observe({type:'layout-shift',buffered:true})
    if(state.event_supported)new PerformanceObserver(list=>{for(const e of list.getEntries())if(e.interactionId)state.interactions[e.interactionId]=Math.max(state.interactions[e.interactionId]??0,e.duration)}).observe({type:'event',buffered:true,durationThreshold:16})
  },{theme})
  const page=await context.newPage(),cdp=await context.newCDPSession(page)
  page.on('pageerror',()=>report.errors.push('Browser page exception'))
  await cdp.send('Network.enable');await cdp.send('Network.setCacheDisabled',{cacheDisabled:true})
  await cdp.send('Emulation.setCPUThrottlingRate',{rate:mobile?4:1})
  await cdp.send('Network.emulateNetworkConditions',{offline:false,latency:150,downloadThroughput:1600000/8,uploadThroughput:750000/8,connectionType:'cellular3g'})
  const js=new Map(),atlas=[],pending=[]
  context.on('response',response=>{
    const url=new URL(response.url());if(url.origin!==base.origin||(!/\.(?:m?js)$/.test(url.pathname)&&!url.pathname.startsWith('/_atlas/')))return
    pending.push((async()=>{if(response.status()!==200)throw new Error('Static asset unavailable');const bytes=await response.body();if(/\.(?:m?js)$/.test(url.pathname))js.set(url.pathname,gzipSync(bytes,{level:9}).length);else{const sizes=await response.request().sizes();if(!Number.isFinite(sizes.responseBodySize)||sizes.responseBodySize<=0)throw new Error('Wire bytes unavailable');atlas.push({path:url.pathname,body_bytes:sizes.responseBodySize})}})().catch(()=>report.errors.push('Static response accounting failed')))
  })
  const settle=async()=>{await page.waitForLoadState('networkidle');await Promise.all(pending)}
  return {context,page,cdp,js,atlas,settle}
}

async function credits(s) {
  const requests=[]
  const record=request=>{const url=new URL(request.url());if(url.pathname==='/dataset-credits.json'||url.pathname.startsWith('/_atlas/credits/')||url.pathname.startsWith('/_atlas/legal/')){if(url.origin!==base.origin||url.search||url.hash||request.headers().referer)report.errors.push('Credit request disclosed lookup association');requests.push(url.pathname)}}
  s.page.on('request',record)
  try {
    if(await s.page.getByTestId('dataset-credits').count()!==1)throw new Error('Dataset credits are not global and unique')
    await s.page.getByTestId('dataset-credits').locator('summary').click()
    const index=await(await s.context.request.get(new URL('/dataset-credits.json',base).href)).json()
    const entry=index.releases.find(x=>x.release_id===candidate.release_id)
    if(!entry||index.current_release_id!==candidate.release_id)throw new Error('Credit index release mismatch')
    const response=await s.context.request.get(new URL(entry.credits_path,base).href),bytes=await response.body()
    if(createHash('sha256').update(bytes).digest('hex')!==entry.credits_sha256)throw new Error('Credit hash mismatch')
    const document=JSON.parse(bytes)
    if(document.format_version!==2||document.mode!=='production'||document.release_id!==candidate.release_id)throw new Error('Credits claim another release, schema or mode')
    await s.page.getByTestId('dataset-credits').locator('.credits-content').filter({hasNotText:'Loading credits'}).waitFor()
    if(document.entries.length)await s.page.getByTestId('dataset-credit').first().waitFor()
    else await s.page.getByText('No dataset attribution is required for this release.',{exact:true}).waitFor()
    const rendered=await s.page.getByTestId('dataset-credit').evaluateAll(nodes=>nodes.map(node=>({name:node.querySelector('a').textContent,text:node.querySelector('p').textContent,url:node.querySelector('a').getAttribute('href'),links:[...node.querySelectorAll('a')].map(a=>({rel:a.rel,policy:a.referrerPolicy}))})))
    if(rendered.length!==document.entries.length)throw new Error('Credit display population differs')
    for(let i=0;i<rendered.length;i++)if(['name','text','url'].some(k=>rendered[i][k]!==document.entries[i][k])||rendered[i].links.some(a=>!a.rel.includes('noopener')||!a.rel.includes('noreferrer')||a.policy!=='no-referrer'))throw new Error('Credit notice/link differs from reviewed bytes')
    const logos=[...new Map(document.entries.filter(entry=>entry.logo).map(entry=>[entry.logo.path,entry.logo])).values()]
    for(const logo of logos){const bytes=await(await s.context.request.get(new URL(logo.path,base).href)).body();if(createHash('sha256').update(bytes).digest('hex')!==logo.sha256)throw new Error('Required logo differs from reviewed bytes')}
    const images=s.page.getByTestId('visible-dataset-credits').locator('img')
    if(await images.count()!==document.entries.filter(entry=>entry.logo).length||!await images.evaluateAll(nodes=>nodes.every(node=>node.complete&&node.naturalWidth>0)))throw new Error('Required dataset logo was not decoded and displayed')
    if(requests.length!==2+logos.length)throw new Error('Credits did not use exactly the global legal assets')
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
  if(value.circles.length!==24||value.fully_visible_nodes!==24)throw new Error('The real graph workload does not paint all24 complete circles')
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
  await page.evaluate(axeSource)
  const value=await page.evaluate(async()=>{const r=await window.axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}});return {violations:r.violations.map(x=>({id:x.id,impact:x.impact,nodes:x.nodes.length})),incomplete:r.incomplete.map(x=>({id:x.id,nodes:x.nodes.length}))}})
  return value
}
async function owner(page,name,ready) {
  await page.getByRole('navigation',{name:'Atlas views'}).getByRole('link',{name,exact:true}).click()
  await page.getByRole('heading',{name,exact:true,level:1}).waitFor();await page.locator(ready).waitFor()
  if(await page.locator('.demo-label').count()||await page.getByRole('alert').count())throw new Error('Production owner route unavailable or labelled synthetic')
  for(const [owner,selector]of Object.entries({Overview:'.fact-list','Observed risk':'.quality-layout','Class C':'.ip-grid',BGP:'.bgp-graph',ASN:'.asn-list'}))
    if(owner!==name&&await page.locator(selector).count())throw new Error('A route duplicated another canonical fact owner')
}

try {
  server=await chromium.launchServer({channel:'chrome',headless:true})
  rootPid=server.process().pid;browser=await chromium.connect(server.wsEndpoint());report.browser=browser.version()
  memoryTimer=setInterval(async()=>{if(memoryBusy)return;memoryBusy=true;try{report.worker_memory_samples.push(await processTreeRSS())}catch{report.errors.push('Browser RSS observation failed')}finally{memoryBusy=false}},100)
  for(const width of [320,390,1280,1440])for(const theme of ['light','dark'])for(let index=1;index<=30;index++){
    const s=await newSample(width,theme),checks=[],row={width,theme,sample:index}
    try {
      await s.page.goto(new URL('/ip/',base).href,{waitUntil:'networkidle'});await s.page.getByRole('textbox',{name:'IP address or ASN'}).waitFor();await s.settle()
      await s.page.waitForFunction(theme=>document.documentElement.classList.contains(theme),theme)
      row.lcp_ms=await s.page.evaluate(()=>window.__atlasProduction.lcp_ms);row.initial_js_gzip_bytes=[...s.js.values()].reduce((a,b)=>a+b,0)
      if(s.atlas.length)throw new Error('Hero requested atlas data before an explicit action')
      checks.push(await accessible(s.page))
      const redirect=await s.context.request.get(new URL('/',base).href,{maxRedirects:0});if(redirect.status()!==302||redirect.headers().location!=='/ip')throw new Error('Actual root HTTP302 missing')
      row.dataset_credits=await credits(s)
      await s.page.getByRole('textbox').fill(corpus.interaction_query);await s.page.getByRole('button',{name:'Look up address'}).click();await s.page.locator('.leaflet-container').waitFor();await s.page.locator('.leaflet-control-attribution').waitFor()
      checks.push(await accessible(s.page))
      await owner(s.page,'Observed risk','.quality-layout,.unrated-panel,.quality-panel');checks.push(await accessible(s.page))
      await owner(s.page,'Class C','.ip-grid');const cell=s.page.getByRole('gridcell').first();await cell.focus();await s.page.keyboard.press('ArrowRight');if(await s.page.getByRole('gridcell').nth(1).getAttribute('tabindex')!=='0')throw new Error('Class C keyboard selection failed');checks.push(await accessible(s.page))
      await owner(s.page,'ASN','.asn-panel,.asn-list,.asn-page,.detail-panel,.status-panel');checks.push(await accessible(s.page))
      await s.page.getByRole('textbox',{name:'IP address or ASN'}).fill(corpus.graph_query);await s.page.getByRole('button',{name:'Look up address'}).click();await s.page.getByRole('heading',{name:'ASN',exact:true,level:1}).waitFor()
      await owner(s.page,'BGP','.bgp-graph svg');const svg=s.page.locator('.bgp-graph svg'),focus=s.page.getByRole('combobox',{name:'Focus observed route'}),count=await focus.locator('option').count()
      if(count<2||await s.page.locator('.graph-node').count()!==24)throw new Error('Production graph corpus must contain24 real observed nodes and selectable routes')
      const layout=await s.page.locator('.graph-node').evaluateAll(nodes=>nodes.map(n=>n.getAttribute('transform')))
      const fit=async()=>{await s.page.getByRole('button',{name:'Fit',exact:true}).click();await svg.scrollIntoViewIfNeeded();await svg.focus();await population(s.page)}
      await fit();const phases=[await graphPhase(s.page,'keyboard-pan',i=>s.page.keyboard.press(i%2?'ArrowLeft':'ArrowRight'))]
      await fit();const b=await svg.boundingBox();await s.page.mouse.move(b.x+b.width/2,b.y+b.height/2);phases.push(await graphPhase(s.page,'wheel-zoom',i=>s.page.mouse.wheel(0,i%2?50:-50)))
      await fit();await focus.focus();await focus.selectOption('-1');phases.push(await graphPhase(s.page,'route-focus',i=>s.page.keyboard.press(i%(2*(count-1))<count-1?'ArrowDown':'ArrowUp')))
      if(JSON.stringify(layout)!==JSON.stringify(await s.page.locator('.graph-node').evaluateAll(nodes=>nodes.map(n=>n.getAttribute('transform')))))throw new Error('Focus reconstructed graph layout')
      row.graph={visible_nodes:24,active_frames:phases};checks.push(await accessible(s.page));await s.settle()
      const metric=await s.page.evaluate(()=>window.__atlasProduction)
      row.interaction_cls=metric.cls_supported?metric.cls:null;row.event_timing_supported=metric.event_supported
      row.interaction_durations_ms=metric.event_supported&&metric.trusted_inputs>0?[16,...Object.values(metric.interactions)]:[]
      row.trusted_input_events=metric.trusted_inputs;row.complete_interaction_script=true
      row.accessibility={engine:'axe-core',version:'4.14.0',violations:checks.flatMap(x=>x.violations),incomplete:checks.flatMap(x=>x.incomplete)}
    } finally {report.populations.push(row);await s.context.close()}
    console.log(`Production browser population ${width}/${theme} ${index}/30`)
  }
  const ipQueries=corpus.queries.filter(query=>isIP(query.q))
  if(ipQueries.length<100)throw new Error('Cold payload corpus needs at least100 real IP queries')
  for(let index=0;index<100;index++){
    const s=await newSample(390,'light'),query=ipQueries[Math.floor(index*ipQueries.length/100)]
    try{await s.page.goto(new URL(`/ip/overview/?q=${encodeURIComponent(query.q)}`,base).href,{waitUntil:'networkidle'});await s.page.getByRole('heading',{name:'Overview',exact:true}).waitFor();await s.page.locator('[role=status]').waitFor({state:'hidden'});await s.settle();if(s.atlas.length<2)throw new Error('Cold lookup did not fetch required controls');report.cold_queries.push({sample:index+1,stratum:query.stratum,atlas_body_bytes:s.atlas.reduce((sum,x)=>sum+x.body_bytes,0),responses:s.atlas})}finally{await s.context.close()}
  }
  for(let index=1;index<=3;index++){
    const s=await newSample(1280,'light')
    try{
      await s.page.goto(new URL(`/ip/overview/?q=${encodeURIComponent(corpus.interaction_query)}`,base).href,{waitUntil:'networkidle'});await s.page.locator('.fact-list').waitFor()
      const result=await s.page.evaluate(async queries=>{const worker=window.__atlasWorkers[0];if(!worker)throw new Error('No actual atlas worker');let id=-1;const lookup=q=>new Promise((resolve,reject)=>{const current=id--;const timeout=setTimeout(()=>{worker.removeEventListener('message',receive);reject(new Error('Worker timing timeout'))},30000);const receive=e=>{if(e.data.id!==current)return;clearTimeout(timeout);worker.removeEventListener('message',receive);if(e.data.error)reject(new Error('Worker lookup failed'));else resolve(e.data.answer)};worker.addEventListener('message',receive);worker.postMessage({action:'lookup',id:current,q})});for(const query of queries)await lookup(query);const samples=[];for(const query of queries){const start=performance.now();await lookup(query);samples.push(performance.now()-start)}return {samples_ms:samples,warmups:queries.length}},corpus.queries.slice(0,1000).map(q=>q.q))
      report.hot_queries.push({context:index,timing:'actual-worker-indexed-lookups',...result})
    }finally{await s.context.close()}
  }
} catch(error) {console.error(error);report.errors.push('production-browser-scenario-failed')}
finally {
  clearInterval(memoryTimer);if(browser)await browser.close();if(server)await server.close()
  report.browser_process_tree_rss_peak_bytes=Math.max(0,...report.worker_memory_samples.filter(x=>x.supported).map(x=>x.rss_bytes))
  await mkdir(new URL('reports/',root),{recursive:true});await writeFile(reportPath,JSON.stringify(report)+'\n')
}
const validation=spawnSync('python',['-c','import json,sys;from tools.release_contract.acceptance import browser_gates,require_all;g=browser_gates(json.load(open(sys.argv[1])));print(json.dumps(g,indent=2));require_all(g)',fileURLToPath(reportPath)],{cwd:root,stdio:'inherit'})
process.exitCode=validation.status===0?0:1
