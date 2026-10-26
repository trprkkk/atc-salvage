# Third-party notices

## libatc (vendor/libatc)

The files in `vendor/libatc/` are derived from **libatc** by h2so5
(https://github.com/h2so5/libatc), which implements the AttacheCase `.atc`
file format.

- Files that are **unchanged** from upstream: `ATCCommon.h`, `ATCLocker.{h,cpp}`,
  `Rijndael.{h,cpp}`, `blowfish.{h,cpp}`, `blowfish.h2`, `isaac.{c,h}`, `standard.h`.
  Used for decryption (`Rijndael`, `blowfish`) and by the test-archive generator
  (`ATCLocker*`, `isaac`).
- Files that are **altered** from upstream: `ATCUnlocker.{h,cpp}`,
  `ATCUnlocker_impl.{h,cpp}`, `ATCLocker_impl.cpp`. Each carries a notice
  after the original licence block describing the changes. Changes add a
  `broken` state flag, keep partially decoded output on a zlib error, avoid
  emitting stale buffer contents when the input ends early, and add a raw
  body-dump helper. `ATCLocker_impl.cpp` additionally fixes a buffer overflow
  in `fillrand()` that only manifests on 64-bit platforms (an 8-byte
  `unsigned long` written into a 4-byte buffer); without it `make test`
  aborts with a stack-smashing error on modern 64-bit Linux.

The upstream copyright and licence notices are preserved in every file. The
licence is the zlib licence (as stated in those headers). Consult the upstream
project for its current terms.

## AttacheCase

AttacheCase is software by HiBARA Software. This project does not include its
code and is not affiliated with it. Format details were derived from the
publicly available reference implementation, not from the proprietary binary.
