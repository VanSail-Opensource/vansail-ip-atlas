import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { parseInput, resolve, validateOrigin } from './query.ts'

const corpus = JSON.parse(readFileSync(new URL('../../fixtures/contracts/queries.json', import.meta.url), 'utf8'))

test('shared Go/TypeScript IP and ASN syntax corpus', async t => {
  assert.equal(corpus.contract_revision, 1)
  assert.equal(corpus.synthetic, true)
  for (const [index, vector] of corpus.inputs.entries()) {
    await t.test(`input ${index}`, () => {
      if (vector.error) {
        assert.throws(() => parseInput(vector.input), { message: vector.error })
      } else {
        const actual = parseInput(vector.input)
        assert.deepEqual(actual, vector.expected)
        assert.deepEqual(parseInput(actual.canonical), actual)
      }
    })
  }
})

test('shared Go/TypeScript route and raw query corpus', async t => {
  for (const [index, vector] of corpus.urls.entries()) {
    await t.test(`URL ${index}`, () => assert.deepEqual(resolve(vector.route, vector.raw), vector.expected))
  }
})

test('origin membership is distinct from syntax', () => {
  for (const vector of corpus.origin_membership) {
    if (vector.valid) validateOrigin(vector.requested, vector.origins)
    else assert.throws(() => validateOrigin(vector.requested, vector.origins), { message: 'origin_not_member' })
  }
})
