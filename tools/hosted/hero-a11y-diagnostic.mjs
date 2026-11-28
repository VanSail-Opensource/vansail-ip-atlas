// Closed diagnostic only. No search input, credentials, corpus, or artifacts.
import { chromium } from 'playwright'
import { readFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { gzipSync } from 'node:zlib'

const origin='https://cfc6ff95.vansail-ip-atlas.pages.dev'
const families=[['hero-headline-accent','.hero h1 span'],['hero-headline','.hero h1'],['hero-eyebrow','.hero .eyebrow'],
  ['hero-copy','.hero-copy'],['hero-footnote','.hero-footnote'],['hero-search','.search-form'],['hero-orbit-ring','.hero-orbit > div'],
  ['hero-orbit','.hero-orbit'],['hero-inner','.hero-inner'],['hero','.hero'],['skip-link','.skip'],['header','.site-header'],['footer','.site-footer'],['main','main'],['shell','.atlas-shell'],['page','body,html']]
const reasons=['bgOverlap','elmPartiallyObscured','elmPartiallyObscuring','outsideViewport','bgImage','bgGradient','imgNode',
  'fgAlpha','colorParse','pseudoContent','complexTextShadows','emptyValue','shortTextContent','equalRatio','nonBmp','fgContrast','hidden']
const rules=['color-contrast','scrollable-region-focusable','svg-img-alt','label','nested-interactive','target-size',
  'link-in-text-block','button-name','link-name','aria-valid-attr','aria-valid-attr-value','heading-order']

async function audit(page,source) {
  await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))))
  await page.evaluate(source)
  return page.evaluate(async ({families,reasons,rules})=>{
    const result=await window.axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}})
    const element=target=>{
      try {return target?.length===1 && typeof target[0]==='string' ? document.querySelector(target[0]) : null} catch {return null}
    }
    const classify=el=>families.find(([,selector])=>el?.closest(selector))?.[0]??'other'
    const related=nodes=>[...new Set(nodes.map(n=>classify(element(n.target))))].sort()
    return ['violations','incomplete'].flatMap(outcome=>result[outcome].flatMap(rule=>rule.nodes.map(node=>{
      const checks=[...node.any,...node.all,...node.none]
      return {outcome,rule:rules.includes(rule.id)?rule.id:'other',category:classify(element(node.target)),
        reason:checks.map(x=>x.data?.messageKey).find(x=>reasons.includes(x))??'other',related:related(checks.flatMap(x=>x.relatedNodes??[]))}
    })))
  },{families,reasons,rules})
}

let server,browser,context
try {
  const theme=process.env.ATLAS_HERO_THEME
  if (!['light','dark'].includes(theme)) throw new Error()
  const source=await readFile(createRequire(import.meta.url).resolve('axe-core/axe.min.js'),'utf8')
  server=await chromium.launchServer({channel:'chrome',headless:true})
  browser=await chromium.connect(server.wsEndpoint())
  context=await browser.newContext({viewport:{width:320,height:844},deviceScaleFactor:2,colorScheme:theme,reducedMotion:'no-preference',serviceWorkers:'block'})
  let atlasRequests=0, unexpected=false
  await context.route('**/*',route=>{
    const url=new URL(route.request().url())
    if (url.origin!==origin || url.hash || (url.search && !/^\?_b=[0-9a-f]{32}$/.test(url.search))) {unexpected=true;return route.abort('blockedbyclient')}
    if (url.pathname.startsWith('/_atlas/') || url.pathname==='/dataset-credits.json') {atlasRequests++;return route.abort('blockedbyclient')}
    return route.continue()
  })
  await context.addInitScript(theme=>localStorage.setItem('nuxt-color-mode',theme),theme)
  const page=await context.newPage(),cdp=await context.newCDPSession(page)
  await cdp.send('Network.enable');await cdp.send('Network.setCacheDisabled',{cacheDisabled:true})
  await cdp.send('Emulation.setCPUThrottlingRate',{rate:4})
  await cdp.send('Network.emulateNetworkConditions',{offline:false,latency:150,downloadThroughput:1600000/8,uploadThroughput:750000/8,connectionType:'cellular3g'})
  const pending=[]
  context.on('response',response=>{
    if (/\.(?:m?js)$/.test(new URL(response.url()).pathname)) pending.push(response.body().then(bytes=>gzipSync(bytes,{level:9}).length).catch(()=>{unexpected=true}))
  })
  await page.goto(origin+'/ip/',{waitUntil:'networkidle'})
  await page.getByRole('textbox',{name:'IP address or ASN'}).waitFor()
  await page.waitForLoadState('networkidle');await Promise.all(pending)
  await page.waitForFunction(theme=>document.documentElement.classList.contains(theme),theme)
  if (unexpected||atlasRequests||await page.locator('.hero-orbit').count()!==1) throw new Error()
  console.log(JSON.stringify({nonqualifying:true,route:'hero',theme,variant:'unchanged',findings:await audit(page,source)}))
  await page.locator('.hero-orbit').evaluate(el=>el.style.setProperty('display','none','important'))
  console.log(JSON.stringify({nonqualifying:true,route:'hero',theme,variant:'without-ornament',findings:await audit(page,source)}))
  if (unexpected||atlasRequests) throw new Error()
} catch {
  console.error('Non-qualifying hero diagnostic failed before a complete comparison.')
  process.exitCode=1
} finally {
  await context?.close();await browser?.close();await server?.close()
}
