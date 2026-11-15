// Exercise the exact emitted worker on the accepted legal maximum VIA3 profile.
// Chrome is already running in its own cgroup from process birth. Node is outside it.
import { chromium } from 'playwright'
import { readFile, readdir, writeFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import { createHash } from 'node:crypto'
import { resolve, join, sep } from 'node:path'
const publicRoot=resolve(process.env.ATLAS_MEMORY_PUBLIC)
const profile=JSON.parse(await readFile(process.env.ATLAS_MEMORY_PROFILE,'utf8'))
const fixtureRoot=resolve('build-private/worker-profile')
const workers=(await readdir(join(publicRoot,'_nuxt'))).filter(name=>/^atlas-[A-Za-z0-9_-]+\.js$/.test(name))
if(workers.length!==1)throw new Error('One exact emitted atlas worker is required')
const workerPath='/_nuxt/'+workers[0]
const workerBytes=await readFile(join(publicRoot,workerPath))
const report={browser:null,worker_sha256:createHash('sha256').update(workerBytes).digest('hex'),completed_cases:0,cases:[],object_hashes:[],retained_answer_bytes:[],errors:[]}
const requestedObjects=new Set()
const server=createServer(async(req,res)=>{
  try{
    const path=new URL(req.url,'http://localhost').pathname
    if(path==='/'){res.writeHead(200,{'Content-Type':'text/html'});res.end('<!doctype html><title>Atlas memory acceptance</title>');return}
    const base=path.startsWith('/_atlas/')?fixtureRoot:publicRoot
    const file=resolve(base,path.startsWith('/_atlas/')?path.slice(8):'.'+path)
    if(!file.startsWith(base+sep))throw new Error('path')
    const bytes=await readFile(file)
    if(/^\/_atlas\/objects\/[a-f0-9]{64}\.via3$/.test(path))requestedObjects.add(path.split('/').at(-1).slice(0,-5))
    res.writeHead(200,{'Content-Type':file.endsWith('.js')?'text/javascript':file.endsWith('.json')?'application/json':'application/octet-stream','Cache-Control':'no-store'})
    res.end(bytes)
  }catch{res.writeHead(404);res.end()}
})
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve))
let browser
try{
  browser=await chromium.connectOverCDP(process.env.ATLAS_MEMORY_CDP)
  report.browser=browser.version()
  const context=await browser.newContext()
  const page=await context.newPage()
  const origin=`http://127.0.0.1:${server.address().port}`
  await context.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort())
  await page.goto(origin)
  const measured=await page.evaluate(async({workerPath,cases})=>{
    const worker=new Worker(workerPath,{type:'module'})
    let id=0;const completed=[],retained=[]
    const invoke=test=>new Promise((resolve,reject)=>{
      const request=++id,timer=setTimeout(()=>reject(new Error('memory case timed out')),60000)
      const receive=event=>{if(event.data.id!==request)return;clearTimeout(timer);worker.removeEventListener('message',receive)
        if(test.expected_error?event.data.error!==test.expected_error:!!event.data.error){reject(new Error('memory case result differs'));return}
        resolve(event.data.answer)}
      worker.addEventListener('message',receive);worker.postMessage({id:request,action:test.action,q:test.q,cursor:test.cursor??0})
    })
    for(const test of cases){
      if(!['lookup','classC','prefixes'].includes(test.action)||typeof test.q!=='string')throw new Error('invalid memory profile case')
      const answer=await invoke(test)
      if(!test.expected_error&&(answer===undefined||answer===null))throw new Error('memory case did not materialize answer')
      const answerBytes=answer===undefined?0:new TextEncoder().encode(JSON.stringify(answer)).length
      if(test.answer_bytes!==undefined&&answerBytes!==test.answer_bytes)throw new Error('materialized answer boundary differs')
      if(test.retain_answer)retained.push(answer)
      // Hold the structured clone while repeating the real lookup/IDB path.
      const repeated=await invoke(test)
      const repeatedBytes=repeated===undefined?0:new TextEncoder().encode(JSON.stringify(repeated)).length
      if(repeatedBytes!==answerBytes)throw new Error('repeat lookup changed materialized answer size')
      completed.push({name:test.name,answer_bytes:answerBytes,repeat_answer_bytes:repeatedBytes,retained_answers:retained.length})
    }
    // Read every retained object after the resident-limit cases. Merely retaining
    // an array length would not prove the earlier structured clone remained live.
    const retainedAnswerBytes=retained.map(answer=>new TextEncoder().encode(JSON.stringify(answer)).length)
    worker.terminate();return {cases:completed,retained_answer_bytes:retainedAnswerBytes}
  },{workerPath,cases:profile.cases})
  report.cases=measured.cases;report.completed_cases=measured.cases.length;report.retained_answer_bytes=measured.retained_answer_bytes;report.object_hashes=[...requestedObjects].sort()
  for(const test of profile.cases)for(const hash of test.required_objects??[])
    if(!requestedObjects.has(hash))throw new Error('required boundary object was not actually fetched')
  await context.close()
}catch{report.errors.push('worker-memory-workload-failed')}
finally{
  // Disconnect, do not kill Chrome: the parent must read memory.peak before stop.
  await writeFile(process.env.ATLAS_MEMORY_CASE_REPORT,JSON.stringify(report)+'\n')
  server.close()
}
process.exit(report.errors.length?1:0)
