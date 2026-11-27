import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { BrowserContractFailure, browserDiagnostics, browserFailureMarker } from './browser-failures.mjs'

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
