// Diagnostic only. No corpus, credentials, output files, or release evidence.
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { chromium } from 'playwright'
import { submitLookup } from './production-interactions.mjs'
import { graphVisibleNodeCount } from './performance-gates.mjs'

const preview = 'https://694207ac.vansail-ip-atlas.pages.dev'
const release = '1551ec4a5bf10be54247a62ae39bccc02a815a16fcd5d3c52eeece057799c0d2'
const workerHash = '64ba4fbc62b5023759513ba9763b3160c52b33abe1e0e4621870b8bcfd3539ff'
const tags = ['wcag2a','wcag2aa','wcag21aa']
const knownClasses = ['graph-node-label','empty-graph-label','graph-node','graph-edge','graph-viewport','graph-toolbar',
  'graph-actions','plain-button','graph-legend','graph-caption','graph-original','bgp-graph','bgp-controls','demo-label',
  'query-input','search-submit','view-nav','site-header','site-footer','view-heading','rpki-snapshots']
const knownTags = ['a','b','button','circle','code','dd','details','div','dt','foreignobject','g','h1','h2','input','label',
  'li','ol','option','p','path','section','select','span','summary','svg','text','ul']
const knownReasons = ['bgGradient','bgImage','bgOverlap','colorParse','complexTextShadows','elmPartiallyObscured',
  'elmPartiallyObscuring','emptyValue','equalRatio','fgAlpha','fgOnShadowColor','hidden','imgNode','nonBmp',
  'obscured','outsideViewport','partiallyObscured','partiallyObscuredNonTabbable','pseudoContent','shadowOnBgColor','shortTextContent']
const safeGeometry = ['inside','clipped','offscreen','empty','unresolved']
const safeBacking = ['opaque','translucent','gradient','image','none','unresolved']
const hash = bytes => createHash('sha256').update(bytes).digest('hex')
const canonical = v => v === null || typeof v !== 'object' ? JSON.stringify(v) : Array.isArray(v) ?
  `[${v.map(canonical).join(',')}]` : `{${Object.keys(v).sort().map(k=>`${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`

function fixtureFiles(fixture) {
  if (fixture.manifest.mode!=='synthetic' || !fixture.vectors.some(row=>row.q==='AS424240')) throw new Error()
  const files=new Map()
  for (const {info,base64} of fixture.objects) {
    const bytes=Buffer.from(base64,'base64')
    if (bytes.length!==info.bytes || hash(bytes)!==info.sha256 || !fixture.manifest.objects.some(row=>canonical(row)===canonical(info))) throw new Error()
    files.set(`/_atlas/objects/${info.sha256}.via3`,bytes)
  }
  const descriptor={...fixture.manifest};delete descriptor.release_id
  descriptor.valid_from=Math.floor(Date.now()/1000)-60
  descriptor.valid_until=descriptor.valid_from+720*3600
  const id=hash(canonical(descriptor)),manifest=Buffer.from(canonical({...descriptor,release_id:id}))
  const manifestPath=`/_atlas/releases/${id}/manifest.json`
  files.set(manifestPath,manifest)
  files.set('/_atlas/current.json',Buffer.from(canonical({format_version:3,release_id:id,manifest_path:manifestPath,manifest_sha256:hash(manifest)})))
  const credits=Buffer.from(canonical({format_version:2,mode:'synthetic',release_id:id,entries:[]})),creditHash=hash(credits)
  const creditsPath=`/_atlas/credits/${creditHash}.json`
  files.set(creditsPath,credits)
  files.set('/dataset-credits.json',Buffer.from(canonical({format_version:1,current_release_id:id,releases:[{release_id:id,credits_path:creditsPath,credits_sha256:creditHash}]})))
  return {id,files}
}

async function audit(page,axeSource,rules) {
  await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))))
  await page.evaluate(axeSource)
  const raw=await page.evaluate(async ({tags,knownTags,knownClasses,knownReasons})=>{
    const terminal = node => {
      // Never return the selector, attributes, text, CSS values, or exact coordinates.
      let element
      try { if (node.target?.length===1 && typeof node.target[0]==='string') element=document.querySelector(node.target[0]) } catch {}
      const region=element&&knownClasses.find(name=>element.closest(`.${name}`))
      let geometry='unresolved',backing='unresolved',covered=false
      if (element) {
        const rect=element.getBoundingClientRect()
        let left=0,top=0,right=innerWidth,bottom=innerHeight
        for (let current=element.parentElement;current;current=current.parentElement) {
          const style=getComputedStyle(current),r=current.getBoundingClientRect()
          if (/(hidden|auto|scroll|clip)/.test(style.overflowX)) {left=Math.max(left,r.left);right=Math.min(right,r.right)}
          if (/(hidden|auto|scroll|clip)/.test(style.overflowY)) {top=Math.max(top,r.top);bottom=Math.min(bottom,r.bottom)}
        }
        geometry=rect.width<=0||rect.height<=0?'empty':rect.right<=left||rect.left>=right||rect.bottom<=top||rect.top>=bottom?'offscreen':
          rect.left<left||rect.top<top||rect.right>right||rect.bottom>bottom?'clipped':'inside'
        const hit=document.elementFromPoint((rect.left+rect.right)/2,(rect.top+rect.bottom)/2)
        covered=!!hit&&hit!==element&&!element.contains(hit)&&!hit.contains(element)
        backing='none'
        for (let current=element;current;current=current.parentElement) {
          const style=getComputedStyle(current),image=style.backgroundImage,color=style.backgroundColor
          if (image!=='none') {backing=image.includes('gradient(')?'gradient':'image';break}
          if (color.startsWith('rgb(')) {backing='opaque';break}
          if (color.startsWith('rgba(')&&Number(color.slice(0,-1).split(',').at(-1))>0) {backing='translucent';break}
        }
      }
      const reasons=[...new Set([...node.any,...node.all,...node.none].map(c=>c.data?.messageKey).filter(k=>knownReasons.includes(k)))].sort()
      return {tag:knownTags.includes(element?.localName.toLowerCase())?element.localName.toLowerCase():'other',
        class:region??'other',geometry,backing,covered,focused:element===document.activeElement,reasons}
    }
    const result=await window.axe.run(document,{runOnly:{type:'tag',values:tags}})
    const simplify=rows=>rows.map(r=>({id:r.id,nodes:r.nodes.slice(0,24).map(terminal)}))
    return {violations:simplify(result.violations),incomplete:simplify(result.incomplete)}
  },{tags,knownTags,knownClasses,knownReasons})
  const safe=(value,options,fallback)=>options.includes(value)?value:fallback
  return Object.fromEntries(['violations','incomplete'].map(group=>[group,raw[group].slice(0,100).map(row=>({
    rule:rules.has(row.id)?row.id:'unknown-rule', nodes:row.nodes.slice(0,24).map(node=>({
      tag:safe(node.tag,knownTags,'other'),class:safe(node.class,knownClasses,'other'),
      geometry:safe(node.geometry,safeGeometry,'unresolved'),backing:safe(node.backing,safeBacking,'unresolved'),
      covered:node.covered===true,focused:node.focused===true,reasons:node.reasons.filter(x=>knownReasons.includes(x)),
    })),
  }))]))
}

async function visible(svg) {
  const boxes=await svg.evaluate(element=>{
    const box=node=>{const r=node.getBoundingClientRect();return {left:r.left,top:r.top,right:r.right,bottom:r.bottom}}
    const svg=box(element),view=box(element.closest('.graph-viewport'))
    return {svg_bounds:svg,visible_bounds:{left:Math.max(0,svg.left,view.left),top:Math.max(0,svg.top,view.top),
      right:Math.min(innerWidth,svg.right,view.right),bottom:Math.min(innerHeight,svg.bottom,view.bottom)},
      circles:[...element.querySelectorAll('.graph-node circle')].map(box)}
  })
  if (boxes.circles.length!==24 || graphVisibleNodeCount(boxes)!==24) throw new Error()
}

async function phase(page,svg,action) {
  await visible(svg)
  await page.evaluate(()=>{const s=window.__diagFrames={times:[],stop:false};const tick=t=>{if(!s.stop){s.times.push(t);requestAnimationFrame(tick)}};requestAnimationFrame(tick)})
  const start=performance.now();let count=0,next=1000
  while (performance.now()-start<10000) {
    await action(count++)
    await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(resolve)))
    if (performance.now()-start>=next) {await visible(svg);next+=1000}
  }
  await page.evaluate(()=>{window.__diagFrames.stop=true})
  await visible(svg)
}

async function sample(browser,theme,fixture,axeSource,rules) {
  let context,stage='context',unexpected=false,pageError=false
  const result=(phase,findings)=>console.log(JSON.stringify({theme,phase,...findings}))
  try {
    context=await browser.newContext({viewport:{width:320,height:844},deviceScaleFactor:2,colorScheme:theme,
      reducedMotion:'no-preference',serviceWorkers:'block',acceptDownloads:false})
    await context.route('**/*',route=>{
      const url=new URL(route.request().url())
      if (url.origin!==preview || !['GET','HEAD'].includes(route.request().method())) {unexpected=true;return route.abort('blockedbyclient')}
      if (!url.pathname.startsWith('/_atlas/') && url.pathname!=='/dataset-credits.json') return route.continue()
      const bytes=fixture.files.get(url.pathname)
      if (!bytes || url.search || url.hash) {unexpected=true;return route.abort('blockedbyclient')}
      return route.fulfill({status:200,contentType:url.pathname.endsWith('.json')?'application/json':'application/octet-stream',
        headers:{'content-length':String(bytes.length)},body:bytes})
    })
    await context.routeWebSocket('**/*',ws=>{unexpected=true;ws.close()})
    await context.addInitScript(theme=>{
      localStorage.setItem('nuxt-color-mode',theme)
      const NativeWorker=window.Worker
      window.__diagWorkers=[]
      window.Worker=class extends NativeWorker {constructor(...args) {super(...args);window.__diagWorkers.push(String(args[0]));this.addEventListener('message',e=>{
        const a=e.data.answer;if(a?.q&&a?.releaseId)window.__atlasLastLookup={q:a.q,releaseId:a.releaseId,synthetic:a.synthetic}
      })}}
    },theme)
    const page=await context.newPage(),cdp=await context.newCDPSession(page),workerChecks=new Map()
    page.on('pageerror',()=>{pageError=true})
    context.on('response',response=>{
      const u=new URL(response.url())
      if (u.origin===preview && /^\/_nuxt\/atlas-[\w-]+\.js$/.test(u.pathname))
        workerChecks.set(u.href,response.body().then(bytes=>response.ok()&&hash(bytes)===workerHash).catch(()=>false))
    })
    await cdp.send('Network.enable');await cdp.send('Network.setCacheDisabled',{cacheDisabled:true})
    await cdp.send('Emulation.setCPUThrottlingRate',{rate:4})
    await cdp.send('Network.emulateNetworkConditions',{offline:false,latency:150,downloadThroughput:1600000/8,uploadThroughput:750000/8,connectionType:'cellular3g'})
    stage='fixture'
    await page.goto(`${preview}/ip/`,{waitUntil:'networkidle'})
    await submitLookup(page,'AS424240',{releaseId:fixture.id,synthetic:true})
    await page.getByRole('navigation',{name:'Atlas views'}).getByRole('link',{name:'BGP',exact:true}).click()
    const svg=page.locator('.bgp-graph svg'),focus=page.getByRole('combobox',{name:'Focus observed route'})
    await svg.waitFor();await page.locator('.demo-label').waitFor();await page.waitForLoadState('networkidle')
    const urls=[...new Set(await page.evaluate(()=>window.__diagWorkers))]
    stage='worker'
    if (urls.length!==1 || !await workerChecks.get(new URL(urls[0],preview).href)) throw new Error()
    const count=await focus.locator('option').count()
    if (count<2) throw new Error()
    const layout=()=>page.locator('.graph-node').evaluateAll(nodes=>nodes.map(node=>node.getAttribute('transform')))
    const originalLayout=await layout()
    stage='fit'
    const fit=async()=>{await page.getByRole('button',{name:'Fit',exact:true}).click();await svg.scrollIntoViewIfNeeded();await svg.focus();await visible(svg)}
    const checkpoint=async name=>{if(process.env.ATLAS_GRAPH_CHECKPOINTS==='1')result(name,await audit(page,axeSource,rules))}
    await fit();await checkpoint('fit')
    stage='keyboard-pan'
    await phase(page,svg,i=>page.keyboard.press(i%2?'ArrowLeft':'ArrowRight'));await checkpoint('keyboard-pan')
    stage='wheel-zoom'
    await fit();const bounds=await svg.boundingBox();await page.mouse.move(bounds.x+bounds.width/2,bounds.y+bounds.height/2)
    await phase(page,svg,i=>page.mouse.wheel(0,i%2?50:-50));await checkpoint('wheel-zoom')
    stage='route-focus'
    await fit();await focus.focus();await focus.selectOption('-1')
    await phase(page,svg,i=>page.keyboard.press(i%(2*(count-1))<count-1?'ArrowDown':'ArrowUp'))
    if (JSON.stringify(await layout())!==JSON.stringify(originalLayout)) throw new Error()
    stage='accessibility'
    const findings=await audit(page,axeSource,rules)
    result('route-focus',findings)
    if (findings.violations.length||findings.incomplete.length) process.exitCode=1
    if (unexpected||pageError) {result('runtime',{unexpectedRequest:unexpected,pageError});process.exitCode=1}
  } catch {result(stage,{completed:false});process.exitCode=1}
  finally {if(context)await context.close().catch(()=>{})}
}

let browser,server
try {
  const configured=process.env.ATLAS_GRAPH_THEME
  if (configured!==undefined&&!['light','dark'].includes(configured)) throw new Error()
  const pointer=execFileSync('curl',['--proto','=https','--fail','--silent','--max-time','15',
    '--max-filesize','8192',`${preview}/_atlas/current.json`],{stdio:['ignore','pipe','ignore'],maxBuffer:8192})
  if (JSON.parse(pointer).release_id!==release) throw new Error()
  const require=createRequire(import.meta.url),axe=require('axe-core')
  const rules=new Set(axe.getRules(tags).map(r=>r.ruleId)) // Fixed by the locked Axe 4.14.0 dependency.
  const axeSource=await readFile(require.resolve('axe-core/axe.min.js'),'utf8')
  const fixture=fixtureFiles(JSON.parse(await readFile(new URL('../../fixtures/bin/synthetic-graph24-via3.json',import.meta.url))))
  server=await chromium.launchServer({channel:'chrome',headless:true,
    ...(process.env.ATLAS_CHROME_EXECUTABLE?{executablePath:process.env.ATLAS_CHROME_EXECUTABLE}:{})})
  browser=await chromium.connect(server.wsEndpoint())
  if (browser.version()!=='158.0.8127.88') throw new Error()
  for (const theme of configured?[configured]:['light','dark']) await sample(browser,theme,fixture,axeSource,rules)
} catch {console.log('{"phase":"setup","completed":false}');process.exitCode=1}
finally {if(browser)await browser.close().catch(()=>{});if(server)await server.close().catch(()=>{})}
