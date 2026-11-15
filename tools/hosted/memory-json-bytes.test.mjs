import assert from 'node:assert/strict'
import test from 'node:test'
import { createJSONByteCounter } from './memory-json-bytes.mjs'

test('JSON byte counting preserves multibyte and surrogate boundaries with bounded reusable scratch', () => {
  const native = new TextEncoder(), buffers = new Set()
  const count = createJSONByteCounter({
    encodeInto(text, destination) {
      assert.equal(destination.byteLength, 64 * 1024)
      buffers.add(destination.buffer)
      return native.encodeInto(text, destination)
    },
  })
  for (const value of [null, { escaped: '\n"\\', text: '中国😀' },
    'a'.repeat(65533) + '😀é中', 'a'.repeat(65534) + '😀', '\ud800',
    { text: '中😀'.repeat(1024 * 1024) }]) {
    assert.equal(count(value), Buffer.byteLength(JSON.stringify(value)))
    assert.equal(count(value), Buffer.byteLength(JSON.stringify(value)))
  }
  assert.equal(count(undefined), 0)
  assert.equal(buffers.size, 1)
})
