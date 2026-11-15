// Serialize the whole answer, but reuse bounded encoding scratch for byte counts.
// The original answer and its required retained structured clone remain untouched.
export function createJSONByteCounter(encoder = new TextEncoder()) {
  const scratch = new Uint8Array(64 * 1024)
  return value => {
    if (value === undefined) return 0
    const text = JSON.stringify(value)
    let offset = 0, bytes = 0
    while (offset < text.length) {
      const { read, written } = encoder.encodeInto(text.slice(offset), scratch)
      if (read <= 0) throw new Error('JSON encoding made no progress')
      offset += read
      bytes += written
    }
    return bytes
  }
}
