# Bounded bulk acquisition

`WalkArchive` streams plain, gzip, bzip2, TAR, ZIP/ZIP64 and single-stream XZ
inputs into a parser without extracting files. Existing compressed, decoded,
entry, name, cancellation and traversal limits apply to every format. TAR
wrappers include `tar.gz`, `tar.bz2` and `tar.xz`. Format support grants no source
rights, observed-schema certification or publication proof.

XZ framing follows the [publisher format specification](https://tukaani.org/xz/xz-file-format.txt).
Before decoding, it validates the footer/index CRCs, canonical lengths, all block
headers, the complete byte inventory and aggregate decoded size. The input
profile permits one LZMA2 filter, at most 10,000 blocks, a 1 MiB index and at most
64 MiB dictionary per block. Unsupported filters, concatenation and padding
outside the declared stream are rejected. Each block is decoded only through
its separately bounded compressed range using the pinned LZMA2 implementation;
its actual compressed/decoded sizes, zero padding and CRC32/CRC64/SHA-256 check
must match. A forged index cannot expose an unexamined header to an allocating
general stream decoder. No partially decoded snapshot is accepted on error.

ZIP64 preflight checks counts before `archive/zip` allocates the directory. It
rejects multi-disk, overlapping/truncated directory framing and oversized
extensible sectors. Existing entry checks still enforce byte limits, paths,
regular files, checksums and complete consumption. These are engineering
format/security fixtures; real-source throughput, hosted resource bounds and
individual adapter qualification remain separate gates.
