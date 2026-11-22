# Pinned Zstandard buffer ownership patch

The frozen pnpm lockfile binds the hash of `fzstd@0.1.1.patch` to the upstream
package and its registry integrity. The MIT notice ships with the dependency.
The patch applies the same decoder changes to its ESM and CommonJS entry points.

The Atlas wrapper preflights each frame's size, window, block boundaries and
checksum trailer, then calls `decompressInto(input, output)` with an independent
output array. Each block borrows a view of the already written bytes inside the
frame's window, up to 8 MiB. Match distances and block output stay within those
bounds. The decoder copies each complete block to the output and releases its
own block buffer. It reports the actual bytes written and signals overflow
before copying a block beyond the output.

The wrapper checks the actual output length, verifies the frame checksum and
clears and releases unpublished output on failure. The existing upstream
one-shot and streaming entry points retain their interfaces. The patch releases
decoder-owned compressed-block scratch after copying it and releases the stream
history after the final block.

The required current stable Chrome and pinned Node toolchain support
`ArrayBuffer.transfer`. Codec regressions cover input and output ownership,
retained callback output, split and concatenated frames, the 8 MiB window,
forged output lengths and checksum failures.
