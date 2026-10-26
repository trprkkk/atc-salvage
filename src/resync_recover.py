#!/usr/bin/env python3
"""
resync_recover.py -- best-effort salvage of AttacheCase (Ver.2.x) archives
past the point where normal decompression fails.

Input: the two files written by the companion `dump_body` tool -- the fully
decrypted (but still compressed) body, and a JSON manifest of every entry.
This script never sees the password or any crypto.

Background
  An .atc body is ONE continuous zlib/deflate stream (no per-file flush
  points), encrypted with Rijndael-CBC. CBC decryption recovers after a
  damaged block, but deflate does not: once a byte is wrong, a normal decoder
  cannot resume. Already-compressed data (photos, video) is stored mostly as
  byte-aligned "STORED" deflate blocks, which carry an explicit length (LEN)
  and its one's complement (NLEN) -- that gives structure to re-sync on.

What it does
  1. Decode from the start with zlib until the first error.
  2. Re-validate every file boundary it believes it decoded cleanly (file
     signature check) and retreat to the last verified one, minus one more
     file as a safety margin. Corrupt bytes can be misread as plausible fake
     STORED blocks and decode "successfully" for a while, so the damage can
     start earlier than the reported error.
  3. Search up to --max-skip bytes ahead for byte-aligned STORED-block headers
     (LEN == ~NLEN). Each candidate must (a) decode a sustained run without
     error (--min-valid-run) and (b) line up with the manifest's file layout:
     a file-start signature at the implied position, confirmed across the next
     two files too.
  4. On success, decode the rest with the last 32 KB of known-good output as a
     preset dictionary, zero-fill the lost span (its size is derived from the
     manifest layout, not guessed), and repeat for further gaps.

Limitations
  * The format has NO per-file checksum, so no file can be proven intact.
    Damage lying entirely inside one file (not touching a file boundary) can go
    undetected and that file will still be labelled [ OK ]. Check the files
    next to every reported gap by eye.
  * Alignment after a gap is verified only for file types with a signature
    check: jpg/jpeg/png/gif (scanned for), plus bmp/mp4/mov/m4v/pdf/zip/docx/
    xlsx/pptx (exact-boundary check). For other types nothing verifies that
    recovered content is attached to the right file name; a warning is printed.
  * Heuristic and best-effort. No guarantee of correctness or completeness.

Usage:
    python3 resync_recover.py body.bin manifest.json out_dir [options]
    (see --help; on large, badly damaged archives --max-skip usually has to be
    raised far above its default)
"""
import sys
import os
import json
import zlib
import argparse
import time


def bitshift(data: bytes, n: int) -> bytes:
    """Return `data` as if the deflate bit-reader started n bits later,
    repacked byte-aligned. DEFLATE packs bits LSB-first per byte, which is
    exactly what little-endian big-int shifting gives us for free."""
    if n == 0:
        return data
    val = int.from_bytes(data, byteorder='little')
    val >>= n
    return val.to_bytes(len(data), byteorder='little')


def load_manifest(path):
    with open(path, 'r', encoding='utf-8') as f:
        entries = json.load(f)
    offset = 0
    for e in entries:
        # Defensive: normalize Windows-style separators in case this
        # manifest was produced by an older dump_body build.
        e['name'] = e['name'].replace('\\', '/').lstrip('/')
        e['stream_offset'] = offset
        if not e['is_dir']:
            offset += e['size']
    return entries, offset  # offset ends up as total decompressed size


def entry_for_offset(entries, pos):
    for e in entries:
        if e['is_dir']:
            continue
        if pos < e['stream_offset'] + e['size']:
            return e
    return None


def find_trustworthy_prefix_length(output_bytes: bytes, entries) -> int:
    """A decode reaching some length isn't proof every byte up to there is
    correct: a STORED block's header is only a 16-bit LEN/NLEN check, so a
    long run of corrupted-but-structurally-plausible bytes can be silently
    misinterpreted as several fake blocks before zlib finally notices
    something is wrong. That means the true corruption can start well
    before the byte offset where an error is actually raised.

    We can catch this because we independently know, from the archive's
    own header, where every file is supposed to start and what it should
    look like (a JPEG starts with FFD8FF, etc). Walk file boundaries in
    order and stop at the first one that doesn't check out; only what
    came before that point is trustworthy. Files with no strong magic
    check (magic_ok's fallback) don't invalidate anything by themselves.
    """
    trustworthy = 0
    for e in entries:
        if e['is_dir']:
            continue
        start = e['stream_offset']
        end = start + e['size']
        if end > len(output_bytes):
            break  # ran out of decoded data for this file; nothing more to check
        chunk = output_bytes[start:end]
        if not magic_ok(e['name'], chunk):
            print(f'  -> {e["name"]} at offset {start} does not look like a '
                  f'valid file (magic bytes mismatch) -- decode before this '
                  f'point was silently wrong; treating byte {start} onward as '
                  f'unknown.', file=sys.stderr)
            break
        trustworthy = end
    return trustworthy


def retreat_one_more_file(trustworthy_len: int, entries) -> int:
    """Extra safety margin: magic_ok only checks a file's opening bytes,
    so corruption confined to the tail of the file immediately before a
    detected break can slip through undetected (the byte count still
    comes out right by coincidence). Drop that last "validated" file too
    and retreat to its own start, so it gets flagged instead of silently
    trusted."""
    non_dir = sorted([e for e in entries if not e['is_dir']],
                      key=lambda e: e['stream_offset'])
    last_start = trustworthy_len
    for e in non_dir:
        end = e['stream_offset'] + e['size']
        if end == trustworthy_len:
            last_start = e['stream_offset']
            break
    return last_start


def magic_ok(name: str, data: bytes) -> bool:
    if len(data) < 4:
        return False
    lower = name.lower()
    if lower.endswith('.jpg') or lower.endswith('.jpeg'):
        return data[0:3] == b'\xff\xd8\xff'
    if lower.endswith('.png'):
        return data[0:8] == b'\x89PNG\r\n\x1a\n'
    if lower.endswith('.gif'):
        return data[0:4] == b'GIF8'
    if lower.endswith('.bmp'):
        return data[0:2] == b'BM'
    if lower.endswith(('.mp4', '.mov', '.m4v')):
        return data[4:8] == b'ftyp'
    if lower.endswith('.pdf'):
        return data[0:4] == b'%PDF'
    if lower.endswith(('.zip', '.docx', '.xlsx', '.pptx')):
        return data[0:2] == b'PK'
    return True  # unknown type: no strong check available


def decode_from(data: bytes, wbits, zdict=None, progress_label=None):
    """Decode `data` (zlib- or raw-deflate-formatted) from the start.
    Returns (output_bytes, bad_offset) where bad_offset is None on a
    clean full decode, else the approximate input byte offset of the
    first error, found by binary search over prefix length.

    IMPORTANT for performance: the binary search to pinpoint the exact
    error byte must NOT re-decode the whole prefix from byte 0 on every
    trial -- for a large archive (hundreds of MB) that turns one error
    lookup into dozens of full-archive redecodes. Instead we restart
    each trial from `pos` (the start of the chunk that failed) using raw
    deflate primed with a dictionary built from the output already
    known-good up to `pos`, exactly like the resync logic elsewhere in
    this file. This makes each trial O(chunk size), not O(pos).

    ALSO IMPORTANT: garbage bytes coincidentally interpreted as valid
    DEFLATE can hit a pathological expansion ratio (a "deflate bomb" --
    DEFLATE allows up to roughly 1000:1 expansion via long back-
    references). A single 64KB input chunk decompressed with no output
    cap can then balloon into tens of MB of output and take a very long
    time, all from what is actually just corrupted noise. So each input
    chunk is decompressed with an output cap (using unconsumed_tail to
    keep feeding it), and if the expansion ratio for a single chunk gets
    absurd, we treat that the same as a hard decode error -- a real,
    valid file's compressed data never legitimately expands anywhere
    close to that much for one small piece of input.

    If `progress_label` is given, prints periodic progress to stderr so
    a long-running decode on a large archive doesn't look hung."""
    def new_d():
        return zlib.decompressobj(wbits, zdict=zdict) if zdict is not None else zlib.decompressobj(wbits)

    MAX_OUT_PER_CALL = 1 << 20       # 1 MB per decompress() call
    MAX_EXPANSION_RATIO = 200        # generous vs. real photo/video content

    d = new_d()
    out = bytearray()
    pos = 0
    chunk = 1 << 16
    last_report = time.time()
    while pos < len(data):
        piece = data[pos:pos + chunk]
        piece_out_total = 0
        bomb_detected = False
        try:
            feed = piece
            while True:
                got = d.decompress(feed, MAX_OUT_PER_CALL)
                out += got
                piece_out_total += len(got)
                if not d.unconsumed_tail:
                    break
                if piece_out_total > len(piece) * MAX_EXPANSION_RATIO:
                    bomb_detected = True
                    break
                feed = d.unconsumed_tail
        except zlib.error:
            if progress_label:
                print(f'  [{progress_label}] ...done (hit an error at '
                      f'{pos / (1<<20):.1f} MB)', file=sys.stderr)
            local_zdict = bytes(out[-32768:])
            lo, hi = 0, len(piece)
            while lo < hi:
                mid = (lo + hi) // 2
                d2 = zlib.decompressobj(-15, zdict=local_zdict)
                try:
                    d2.decompress(piece[:mid])
                    lo = mid + 1
                except zlib.error:
                    hi = mid
            bad_offset = pos + lo
            d3 = zlib.decompressobj(-15, zdict=local_zdict)
            try:
                extra_good = d3.decompress(piece[:lo])
            except zlib.error:
                extra_good = b''
            return bytes(out) + extra_good, bad_offset

        if bomb_detected:
            if progress_label:
                print(f'  [{progress_label}] ...done (implausible expansion '
                      f'ratio at {pos / (1<<20):.1f} MB -- treating as '
                      f'corrupted, not a real deflate stream)', file=sys.stderr)
            # Whatever this chunk produced is not trustworthy -- discard
            # it and report the error at the START of this chunk, same
            # shape as a normal zlib.error return.
            out = out[:len(out) - piece_out_total]
            return bytes(out), pos
        pos += chunk
        if progress_label and time.time() - last_report > 5:
            pct = 100 * pos / len(data) if data else 100
            print(f'  [{progress_label}] {pos / (1<<20):.1f} / '
                  f'{len(data) / (1<<20):.1f} MB ({pct:.1f}%)...', file=sys.stderr)
            last_report = time.time()
    if progress_label:
        print(f'  [{progress_label}] ...done ({len(data) / (1<<20):.1f} MB, no error).',
              file=sys.stderr)
    return bytes(out), None


def find_stored_block_candidates(body, start, end):
    """Byte-aligned STORED-block headers are self-validating: LEN is
    immediately followed by its one's-complement, NLEN. No content
    knowledge needed -- corruption preserves byte framing (only values
    are wrong), so we only need to scan byte offsets, no bit-shifting.
    NOTE: this structural check alone has a ~1/65536 false-positive rate
    per byte position; over a large corrupted span (megabytes) there WILL
    be coincidental hits. Callers must further validate by actually
    decoding a good stretch of data before trusting a candidate."""
    hits = []
    limit = min(end, len(body) - 4)
    for base in range(start, limit):
        length = body[base] | (body[base + 1] << 8)
        nlen = body[base + 2] | (body[base + 3] << 8)
        if length == (~nlen & 0xFFFF) and 0 < length <= 65535:
            hits.append(base)
    return hits


# How many decompressed bytes a resync candidate must produce, without
# erroring, before we trust it. A false positive (coincidental LEN/NLEN
# match inside still-corrupted garbage) will almost always fail within
# the first block or two; a genuine resync point will sail through this
# comfortably. This is the key defense against silently reporting
# all-zero garbage as "recovered" data.
MIN_VALID_RUN = 1 << 17  # 128 KB


def try_resync(body, bad_offset, known_good_output, entries, max_skip,
                total_size, min_valid_run, huffman_search_limit=0):
    zdict = known_good_output[-32768:] if known_good_output else b''
    known_good_len = len(known_good_output)
    remaining_needed = total_size - known_good_len
    validate_len = min(min_valid_run, remaining_needed)

    # The cheap pre-filter needs to decode far enough to have a real shot
    # at reaching a magic-byte marker even when the resync point lands
    # mid-file: at least one full file's worth (the largest one) past
    # wherever we land, plus margin.
    non_dir_sizes = [e['size'] for e in entries if not e['is_dir']]
    max_entry_size = max(non_dir_sizes) if non_dir_sizes else 0
    cheap_len = min(remaining_needed, max(65536, max_entry_size * 3 + 8192))
    validate_len = max(validate_len, cheap_len)

    # Strategy A (preferred): byte-aligned STORED block headers.
    # Two-stage filtering for speed: first a CHEAP decode just to check
    # whether this candidate's content could plausibly align with a real
    # file boundary (magic bytes), and only for survivors do the
    # expensive full sustained-length decode to confirm.
    checked = 0
    for base in find_stored_block_candidates(body, bad_offset, bad_offset + max_skip):
        length = body[base] | (body[base + 1] << 8)
        block_data_end = base + 4 + length
        if block_data_end + 64 > len(body):
            continue
        # Bound how much we slice for the search/validation trials --
        # near-1:1 compression ratio means this comfortably covers
        # validate_len/cheap_len worth of output without copying the
        # entire remaining archive (which can be hundreds of MB) on
        # every single candidate we try.
        probe_window = max(validate_len, cheap_len) + 65536
        remainder = bytes([0]) + body[base:base + probe_window]

        estimated_gap = max(1, base - bad_offset)
        search_window = max(2_000_000, estimated_gap * 4)

        # Cheap stage: decode enough to have a real shot at reaching a
        # magic-byte marker even if this candidate lands mid-file.
        try:
            dobj_cheap = zlib.decompressobj(-15, zdict=zdict)
            cheap_out = dobj_cheap.decompress(remainder, cheap_len)
        except zlib.error:
            continue
        if len(cheap_out) < 16:
            continue
        if find_gap_size(known_good_len, cheap_out, entries, estimated_gap,
                          search_window) is None:
            continue

        checked += 1
        # Expensive stage: confirm this candidate actually sustains a
        # long clean decode (defends against a coincidental magic-byte
        # match on garbage, which is rare but not impossible).
        try:
            dobj = zlib.decompressobj(-15, zdict=zdict)
            out = dobj.decompress(remainder, validate_len + 4096)
        except zlib.error:
            continue
        if len(out) < validate_len:
            continue
        if find_gap_size(known_good_len, out, entries, estimated_gap,
                          search_window) is not None:
            return ('stored', base)
        if checked >= 200:  # don't let a pathological case run forever
            break

    # Strategy B (fallback): brute-force bit-shift search for a Huffman
    # block. OFF by default (huffman_search_limit=0): across every real
    # test case so far, Strategy A (STORED blocks) has been what
    # actually succeeds -- already-compressed content like photos is
    # overwhelmingly STORED blocks. This search is also far more
    # expensive per byte (8 shift variants x per-candidate decompressor
    # setup), and on a "no candidate anywhere" outcome that cost is
    # pure waste: one real run spent 17 minutes here and found nothing.
    # Enable it with --huffman-search-limit N if Strategy A keeps
    # failing and you're willing to wait.
    huffman_limit = min(max_skip, huffman_search_limit)
    limit = min(bad_offset + huffman_limit, len(body) - 64)
    for base in range(bad_offset, max(bad_offset, limit)):
        probe_head = body[base: base + 64]
        if len(probe_head) < 64:
            break
        for shift in range(8):
            head = probe_head if shift == 0 else bitshift(probe_head, shift)
            try:
                dobj = zlib.decompressobj(-15, zdict=zdict)
                head_out = dobj.decompress(head)
            except zlib.error:
                continue
            if len(head_out) < 16:
                continue
            # Cheap prefilter passed; now do the expensive full validation
            # only for candidates that got this far. Bound the window we
            # bit-shift so this stays cheap even on huge archives.
            window_len = validate_len + (1 << 20)
            full_remaining = body[base: base + window_len]
            candidate = full_remaining if shift == 0 else bitshift(full_remaining, shift)
            try:
                dobj2 = zlib.decompressobj(-15, zdict=zdict)
                out2 = dobj2.decompress(candidate, validate_len + 4096)
            except zlib.error:
                continue
            if len(out2) < validate_len:
                continue
            estimated_gap = max(1, base - bad_offset)
            if find_gap_size(known_good_len, out2, entries, estimated_gap,
                              search_window=max(2_000_000, estimated_gap * 4)) is not None:
                return ('huffman', base, shift)
    return None


def write_files(entries, output_bytes, out_dir, gap_ranges=None):
    gap_ranges = gap_ranges or []
    counts = {'ok': 0, 'gap': 0, 'part': 0, 'unwritten': 0}
    for e in entries:
        if e['is_dir']:
            os.makedirs(os.path.join(out_dir, e['name']), exist_ok=True)
            continue
        start = e['stream_offset']
        end = start + e['size']
        path = os.path.join(out_dir, e['name'])
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        if start >= len(output_bytes):
            counts['unwritten'] += 1
            continue
        overlap = any(gs < end and ge > start for gs, ge in gap_ranges)
        if end > len(output_bytes):
            chunk = output_bytes[start:len(output_bytes)]
            with open(path, 'wb') as f:
                f.write(chunk)
            counts['part'] += 1
            print(f'[PART] {e["name"]} -- {len(chunk)}/{e["size"]} bytes', file=sys.stderr)
            continue
        chunk = output_bytes[start:end]
        with open(path, 'wb') as f:
            f.write(chunk)
        if overlap:
            counts['gap'] += 1
            print(f'[GAP ] {e["name"]} ({len(chunk)} bytes, but overlaps an '
                  f'unrecoverable region -- see notes above)', file=sys.stderr)
        else:
            counts['ok'] += 1
            print(f'[ OK ] {e["name"]} ({len(chunk)} bytes)', file=sys.stderr)
    return counts


# Extensions for which magic_ok() performs a real signature check.
_CHECKED_EXTS = ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.mp4', '.mov',
                 '.m4v', '.pdf', '.zip', '.docx', '.xlsx', '.pptx')


def warn_if_unverifiable(entries):
    files = [e for e in entries if not e['is_dir']]
    unchecked = [e for e in files if not e['name'].lower().endswith(_CHECKED_EXTS)]
    if unchecked:
        print(f'WARNING: {len(unchecked)} of {len(files)} files have an extension with '
              f'no signature check (e.g. {unchecked[0]["name"]}).\n'
              f'  After a gap, nothing verifies that their recovered content is attached '
              f'to the right file name; treat anything recovered past the first gap for '
              f'those files as unverified.', file=sys.stderr)


def input_offset_for_output_length(data: bytes, wbits, zdict, target_len: int) -> int:
    """Find (approximately) the smallest prefix of `data` that decodes to
    at least `target_len` output bytes. Deliberately NOT implemented as a
    from-scratch binary search: whether decompressing an arbitrary prefix
    raises an exception isn't monotonic in prefix length once corrupted
    bytes are involved (a slightly different cut point can dodge or hit a
    bad byte unpredictably), which breaks binary search's assumptions.
    Instead we do a single incremental forward pass with one persistent
    decompressor -- exactly how decode_from() itself works -- and stop as
    soon as cumulative output reaches target_len."""
    d = zlib.decompressobj(wbits, zdict=zdict) if zdict is not None else zlib.decompressobj(wbits)
    produced = 0
    consumed = 0
    step = 4096
    while consumed < len(data):
        piece = data[consumed:consumed + step]
        try:
            out = d.decompress(piece)
        except zlib.error:
            return consumed + len(piece)  # best effort: end of this chunk
        produced += len(out)
        consumed += len(piece)
        if produced >= target_len:
            return consumed
    return consumed


# Which magic-byte pattern to scan for, keyed by the check magic_ok()
# would apply. Only formats with a short, distinctive fixed signature are
# worth scanning for; anything else falls back to length-only trust.
_SCAN_MAGIC = {
    'jpg': (b'\xff\xd8\xff', 0),
    'jpeg': (b'\xff\xd8\xff', 0),
    'png': (b'\x89PNG\r\n\x1a\n', 0),
    'gif': (b'GIF8', 0),
}


def _ext(name):
    dot = name.rfind('.')
    return name[dot + 1:].lower() if dot != -1 else ''


def find_gap_size(known_good_len, piece_out, entries, estimated_gap, search_window):
    """The gap doesn't necessarily end exactly on a file boundary -- it
    very often ends partway through one. So rather than only checking
    "does piece_out start with the right magic bytes", scan piece_out
    for an occurrence of a recognizable file-start signature anywhere
    near the estimate, then confirm it's not a coincidence by checking
    that the FOLLOWING file (whose position is then fully determined)
    also starts correctly. Falls back to the simple boundary-exact check
    for archives without any scannable format, or when nothing confirms."""
    non_dir = [e for e in entries if not e['is_dir']]
    approx_target = known_good_len + estimated_gap

    # Group scan positions by which magic pattern to look for, based on
    # entries expected to be near the estimate.
    nearby = [e for e in non_dir if abs(e['stream_offset'] - approx_target) <= search_window]
    exts = {_ext(e['name']) for e in nearby if _ext(e['name']) in _SCAN_MAGIC}

    lo = 0
    hi = len(piece_out)
    for ext in exts:
        pattern, _ = _SCAN_MAGIC[ext]
        idx = lo
        while True:
            pos = piece_out.find(pattern, idx, hi)
            if pos == -1:
                break
            idx = pos + 1
            # Find the entry whose stream_offset best matches "this
            # occurrence starts here", i.e. entry.stream_offset - pos
            # would be piece_out's implied absolute start.
            best = min(nearby, key=lambda e: abs((e['stream_offset'] - pos) - approx_target), default=None)
            if best is None:
                continue
            implied_gap = best['stream_offset'] - known_good_len - pos
            if implied_gap < 0:
                continue
            chunk = piece_out[pos:pos + best['size']]
            if len(chunk) < min(best['size'], 4) or not magic_ok(best['name'], chunk):
                continue
            # Confirm with the NEXT TWO files too (when reachable) --
            # requiring a 3-file chain to line up makes a coincidental
            # false match astronomically unlikely, at the cost of
            # needing a slightly longer decode to check against.
            idx_in_entries = non_dir.index(best)
            ok_confirm = True
            cursor = pos + best['size']
            for j in range(1, 3):
                if idx_in_entries + j >= len(non_dir):
                    break
                nxt = non_dir[idx_in_entries + j]
                nxt_chunk = piece_out[cursor:cursor + nxt['size']]
                if len(nxt_chunk) < min(nxt['size'], 4):
                    break  # not enough decoded yet to confirm -- allow it
                if not magic_ok(nxt['name'], nxt_chunk):
                    ok_confirm = False
                    break
                cursor += nxt['size']
            if not ok_confirm:
                continue
            return implied_gap

    # Fallback: the original exact-boundary check (still useful when the
    # gap happens to land exactly on a file start, or for archives with
    # no scannable magic bytes at all).
    for e in sorted(nearby, key=lambda e: abs(e['stream_offset'] - approx_target)):
        gap = e['stream_offset'] - known_good_len
        if gap < 0:
            continue
        chunk = piece_out[:e['size']]
        if len(chunk) >= min(e['size'], 4) and magic_ok(e['name'], chunk):
            return gap
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('body')
    ap.add_argument('manifest')
    ap.add_argument('out_dir')
    ap.add_argument('--max-skip', type=int, default=65536,
                     help='how many bytes past a break point to search (default 65536)')
    ap.add_argument('--min-valid-run', type=int, default=MIN_VALID_RUN,
                     help='how many decompressed bytes a candidate must sustain '
                          'without erroring before it is trusted (default 131072). '
                          'Lower this if resync keeps failing near the very end of '
                          'the archive or right before another genuine gap; raise it '
                          'if you suspect false-positive resyncs (garbage output).')
    ap.add_argument('--huffman-search-limit', type=int, default=0,
                     help='OFF by default (0). This is a separate, much smaller '
                          'search range used ONLY for the slow bit-shift '
                          'Huffman-block fallback search (Strategy B), which is '
                          '~8x more expensive per byte than the STORED-block '
                          'search and, across testing, has never been what '
                          'actually found a real resync point for photo/video-'
                          'like content -- on a "nothing found" outcome it just '
                          'burns time (one run: 17 minutes for nothing). Only set '
                          'this (e.g. 20000) if Strategy A keeps reporting "No '
                          'resync point found" and you are willing to wait.')
    args = ap.parse_args()

    with open(args.body, 'rb') as f:
        body = f.read()
    entries, total_size = load_manifest(args.manifest)
    os.makedirs(args.out_dir, exist_ok=True)
    warn_if_unverifiable(entries)

    print(f'body: {len(body)} bytes, {len(entries)} entries, '
          f'{total_size} bytes expected decompressed total', file=sys.stderr)

    all_output, bad_offset = decode_from(body, 15, progress_label='initial decode')
    print(f'clean decode up to {len(all_output)} decompressed bytes '
          f'(input offset {bad_offset})', file=sys.stderr)

    # A STORED block's integrity check is only a 16-bit LEN/NLEN match,
    # so a run of corrupted bytes can occasionally be misread as several
    # plausible-looking fake blocks before zlib finally notices something
    # is wrong -- meaning the real corruption can start well before the
    # offset zlib actually errors at. Validate every file boundary we
    # think we cleanly decoded and retreat to the last one that actually
    # checks out.
    trustworthy = find_trustworthy_prefix_length(bytes(all_output), entries)
    if bad_offset is not None and trustworthy > 0:
        # Only apply the extra one-file safety margin when there really
        # was a break nearby to worry about -- not for a fully clean
        # decode with nothing adjacent to be suspicious of.
        trustworthy = retreat_one_more_file(trustworthy, entries)
    if trustworthy < len(all_output):
        print(f'Retreating clean-decode boundary from {len(all_output)} to '
              f'{trustworthy} bytes (see note above) -- some of what zlib '
              f'decoded before erroring was actually already wrong.',
              file=sys.stderr)
        all_output = all_output[:trustworthy]
        bad_offset = input_offset_for_output_length(body, 15, None, trustworthy)

    if bad_offset is None and trustworthy >= total_size:
        counts = write_files(entries, bytes(all_output), args.out_dir)
        print('Whole archive decoded cleanly -- nothing more to do.', file=sys.stderr)
        return
    if bad_offset is None:
        # Ran out of input before reaching the expected total (shouldn't
        # normally happen -- treat like any other break and try to resync).
        bad_offset = len(body)

    all_output = bytearray(all_output)
    cur_bad_offset = bad_offset
    gap_count = 0
    final = bytearray(all_output)
    gap_ranges = []

    while True:
        print(f'Searching for a resync point after offset {cur_bad_offset}...',
              file=sys.stderr)
        t_search0 = time.time()
        result = try_resync(body, cur_bad_offset, bytes(all_output), entries,
                             args.max_skip, total_size,
                             args.min_valid_run, args.huffman_search_limit)
        print(f'  ...search took {time.time()-t_search0:.1f}s', file=sys.stderr)
        if result is None:
            print(f'No resync point found within {args.max_skip} bytes after '
                  f'offset {cur_bad_offset}. Stopping.', file=sys.stderr)
            break

        kind = result[0]
        gap_count += 1
        if kind == 'stored':
            base = result[1]
            print(f'--- resync #{gap_count}: STORED-block header found at '
                  f'input offset {base} (skipped {base - cur_bad_offset} bytes) ---',
                  file=sys.stderr)
            remainder = bytes([0]) + body[base:]
        else:
            _, base, shift = result
            print(f'--- resync #{gap_count}: Huffman-block candidate at input '
                  f'offset {base} (skipped {base - cur_bad_offset} bytes, '
                  f'bit-shift {shift}) ---', file=sys.stderr)
            remaining = body[base:]
            remainder = bitshift(remaining, shift) if shift else remaining

        estimated_gap = max(1, base - cur_bad_offset)

        zdict = bytes(all_output[-32768:]) if all_output else b''
        piece_out, piece_bad = decode_from(remainder, -15, zdict=zdict,
                                            progress_label=f'segment #{gap_count} decode')

        # Also retreat piece_out itself if IT silently went wrong for a
        # stretch before erroring (same reasoning as the initial decode).
        known_good_len = len(final)

        print(f'  Pinning exact gap size (scanning {len(piece_out)/(1<<20):.1f} MB '
              f'of recovered data for a file-boundary marker)...', file=sys.stderr)
        t_gap0 = time.time()
        gap_size = find_gap_size(known_good_len, piece_out, entries,
                                  estimated_gap, search_window=max(2_000_000, estimated_gap * 4))
        print(f'  ...done in {time.time()-t_gap0:.1f}s', file=sys.stderr)
        if gap_size is None:
            print(f'  (could not pin an exact file boundary near the estimated '
                  f'{estimated_gap}-byte gap -- using the estimate as-is; this '
                  f'region\'s size may be approximate)', file=sys.stderr)
            gap_size = estimated_gap

        gstart = len(final)
        final += bytes(gap_size)  # zero-filled placeholder of the resolved size
        gap_ranges.append((gstart, gstart + gap_size))

        # Now validate piece_out's OWN internal file boundaries the same
        # way, in case it also silently drifted before its own error.
        # find_trustworthy_prefix_length indexes directly into the buffer
        # it's given, so translate entries into piece_out's own local
        # coordinate frame (piece_out[0] == absolute position
        # piece_abs_start) rather than passing absolute stream_offsets.
        piece_abs_start = len(final)
        shifted_entries = []
        for e in entries:
            if e['is_dir'] or e['stream_offset'] < piece_abs_start:
                continue
            e2 = dict(e)
            e2['stream_offset'] = e['stream_offset'] - piece_abs_start
            shifted_entries.append(e2)
        print(f'  Checking file-boundary markers within this segment...', file=sys.stderr)
        t_val0 = time.time()
        trustworthy_piece = find_trustworthy_prefix_length(piece_out, shifted_entries)
        print(f'  ...done in {time.time()-t_val0:.1f}s', file=sys.stderr)
        if piece_bad is not None and trustworthy_piece > 0:
            trustworthy_piece = retreat_one_more_file(trustworthy_piece, shifted_entries)

        retreated = trustworthy_piece < len(piece_out)
        if retreated:
            print(f'  Retreating this segment from {len(piece_out)} to '
                  f'{trustworthy_piece} bytes for the same reason.', file=sys.stderr)
            # Figure out exactly how far into `remainder` that trustworthy
            # point corresponds to, so the next search resumes from the
            # right place -- NOT from wherever decode_from originally
            # stopped (that position is now known to be untrustworthy
            # too, or at best irrelevant since we're cutting earlier).
            retreat_input_offset = input_offset_for_output_length(
                remainder, -15, zdict, trustworthy_piece)
            piece_out = piece_out[:trustworthy_piece]

        final += piece_out
        all_output += piece_out  # running buffer for zdict continuity only

        if retreated:
            # Treat the discarded tail as needing its own resync search,
            # regardless of whether decode_from itself hit a hard error.
            cur_bad_offset = base + retreat_input_offset
            print(f'Continuing to search for a resync point after the '
                  f'retreat (~input offset {cur_bad_offset})...', file=sys.stderr)
        elif piece_bad is None:
            print('Decoded through to the end of the archive from this point.',
                  file=sys.stderr)
            break
        else:
            cur_bad_offset = base + piece_bad
            print(f'Hit another corrupted region (~input offset '
                  f'{cur_bad_offset}); searching for the next resync point...',
                  file=sys.stderr)

        if len(final) >= total_size:
            break

    # If we stopped short of total_size for any reason (e.g. no further
    # resync point found), pad the remainder as one final unrecoverable
    # gap so file boundaries after it still line up for reporting.
    if len(final) < total_size:
        gstart = len(final)
        final += bytes(total_size - len(final))
        gap_ranges.append((gstart, total_size))

    if gap_ranges:
        print('\nUnrecoverable byte ranges in the reconstructed stream '
              '(filled with zeros below):', file=sys.stderr)
        for gs, ge in gap_ranges:
            affected = [e['name'] for e in entries if not e['is_dir']
                        and e['stream_offset'] < ge and e['stream_offset'] + e['size'] > gs]
            print(f'  [{gs}:{ge}] ({ge-gs} bytes) -- affects: {", ".join(affected) if affected else "(unknown)"}',
                  file=sys.stderr)

    counts = write_files(entries, bytes(final), args.out_dir, gap_ranges)
    gap_total = sum(ge - gs for gs, ge in gap_ranges)
    decoded = max(0, total_size - gap_total)
    pct = 100.0 * decoded / total_size if total_size else 100.0
    # The reconstructed buffer is always zero-padded to the full expected size,
    # so its length says nothing about how much was recovered. Report real numbers.
    print(f'\nDone. {gap_count} corrupted region(s) bridged.\n'
          f'  Decoded data: {decoded} / {total_size} bytes ({pct:.1f}%); '
          f'{gap_total} bytes unrecoverable (zero-filled).\n'
          f'  Files: {counts["ok"]} OK, {counts["gap"]} GAP (overlap a lost region), '
          f'{counts["part"]} PART, {counts["unwritten"]} not written.\n'
          f'  "OK" means "not known to be damaged", not "verified intact". Check the files '
          f'next to every gap by eye.', file=sys.stderr)


if __name__ == '__main__':
    main()
