# Pinned Zstandard buffer ownership patch

`fzstd@0.1.1.patch` retains the upstream package version, registry integrity and
MIT notice. pnpm binds the patch hash in the frozen lockfile. Both ESM and CommonJS
entry points receive the same three changes:

- After either compressed-block scratch copy, detach the old owned scratch
  buffer. The returned block is an independent copy; input, output and history
  buffers are unaffected.
- After a stream's final block has been copied into history, detach that frame's
  owned history buffer before advancing to the checksum or next frame.

This preserves the original allocation, zero-initialization and copy semantics;
it releases backing stores at their last use instead of waiting for garbage
collection. It adds no decoder API and does not inspect private state from the
application wrapper. The wrapper still checks actual emitted length and verifies
the independent frame checksum. Failed frames retain the upstream decoder's
cleanup behavior; the wrapper separately releases its unpublished output.

`ArrayBuffer.transfer` is supported by the required current stable Chrome and
pinned Node toolchain. Recheck ownership when upgrading fzstd. Codec regressions
cover retained callback output, split checksums, concatenated streaming frames,
the 8 MiB history window, forged output lengths and checksum failures.
