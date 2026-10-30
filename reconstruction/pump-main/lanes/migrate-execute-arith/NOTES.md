# Lane migrate-execute-arith

Target: `0x77940` `migrate_v2::execute` (8,832 B). The callgraph census records
diagnostic_similarity 0.201 for this window — the lowest among the large
handlers — and no committed lane documented its arithmetic semantics. This lane
is a static opcode census of the committed capture; it builds nothing and runs
nothing from the binary.

Approach: decode the window straight from `evidence/original/pump/deployed.so`
with a Rust decoder and classify the arithmetic shapes.

## Correction of the first pass (commit b93f2a708)

The first version of this lane claimed the window's odd opcodes
(`0x1d/0x2d/0x3d/0x5d/0xad`) were a SBF reassignment of the eBPF register-jump
family to 128-bit ALU operations, and committed a Python tool plus a
`census.json` that was in fact a Python traceback. Both were wrong.

- **Encoding.** The standard eBPF/SBF reading is correct: those opcodes are
  register-form conditional jumps (`jeq r2, r3, +1`, `jlt r6, r0, +1`, …). The
  SBF VM's own opcode definitions keep both immediate and register jump forms
  (`JEQ64_REG`, `JLT64_REG`, … in the `ebpf` module of the sbpf VM). The
  control-flow test settles it locally too: under the standard reading the
  exhibit at `0x78e28` (`jlt r6, r0, +1` skipping `mov r1, 0`) leaves the
  following branch live — a working overflow guard — while the ALU128 reading
  would make that branch dead code. Raw bytes at `0x78e28`
  (`ad 06 01 00 00 00 00 00`) are an ordinary register jump.
- **Artifact.** The committed `census.json` was a traceback because a shell
  redirection captured a failing run. The Rust tool below writes its output
  files directly and was run twice with byte-identical results.

The erroneous "SBF ALU128 reassignment" claim is retracted in full.

## Tool (Rust, zero dependencies)

`tool/` is a standalone Cargo crate (excluded from the repository workspace):
`sbf_census <capture.so> <capture.json> <vaddr> <length> <listing-out> <census-out>`.

- verifies the capture SHA-256 against `capture.json`'s `payload_sha256`
  (hand-rolled SHA-256, no external crates);
- maps the virtual address through the ELF `PT_LOAD` headers;
- decodes with the standard eBPF/SBF encoding (register jumps included,
  `lddw` paired) and **refuses to census a window that contains an opcode
  outside its tables** instead of guessing;
- classifies compare-guarded checked arithmetic, saturating skip-guards,
  division sites, error-code immediates and 32-bit `lddw` constants;
- writes the listing and census JSON directly (no shell redirection).

Regeneration from `tool/`:

```sh
cargo run --release -- ../../../../../../evidence/original/pump/deployed.so \
  ../../../../../../evidence/original/pump/capture.json 0x77940 8832 \
  ../listing.txt ../census.json
```

## Findings

1. **The original's overflow-checked arithmetic in this window is
   compare-guarded, matching the reconstruction's combinator style.** Exactly
   two sites carry the guard shape:
   - `0x78e18`: `add r6, r1` guarded by `jlt r6, r0, +1` at `0x78e28` — a u64
     add whose result is compared against the first operand; the taken branch
     reaches an error path. Position and operands are consistent with the
     source's `real_quote_reserves.checked_add(post_complete_quote_in)`.
   - `0x786d0`: `sub64` guarded by `jgt` (reg) at `0x786e8`.
   The source expresses three checked operations in `execute` (one add, two
   sub); the third's lowering does not use this guard shape within the census
   window and is flagged for follow-up rather than claimed.
2. **Error constants use a bit-63 form, not the 6000+N range.** The window
   contains no immediate in [6000,7000) via `lddw` or `mov`. Instead it
   repeatedly compares values against `0x800000000000001A` (= 2^63+26, six
   `jeq` sites, e.g. `0x77f08`) and `0x8000000000000017` (= 2^63+23, two
   sites), and separately loads the bare constants 23 (`0x78ed0`, `0x78740`)
   and 26 (`0x79830`, `0x78818` and others) whose values match the sentinel
   low halves. Hypothesis, labeled as such: the original custom-error ABI
   flags program errors with bit 63 and carries the variant index; under the
   reconstructed enum's order (77 variants, `lib.rs`), index 23 is
   `NotEnoughTokensToSell` and index 26 is `DivisionByZero` — the same order
   convention the recovered constant-product fragment confirms for its own
   window (6024=Overflow, 6026=DivisionByZero). Five sentinel checks against
   DivisionByZero with zero division instructions in the window are consistent
   with zero-denominator pre-checks before delegating to helpers that divide.
   Confirming the ABI belongs to callee-window work.
3. **No division, modulus or 64-bit multiplication anywhere** in the window,
   so the migration math performs no curve recomputation — consistent with the
   source, which only adds/subtracts and delegates pool creation to the
   pump_amm CPI.
4. 70 call sites, 1 exit: one function with heavy helper/CPI fan-out. The
   saturating_sub sites of the source live in `init_pump_amm_boost_v2`, which
   is `#[inline(never)]` with its own window — their absence here is
   consistent, not a discrepancy.
5. 34 `lddw` constants total: the two error sentinels above plus 18 distinct
   values in the 0x1b5xxx–0x1bdxxx range (uninterpreted — Anchor
   discriminators/hashes by shape).

## Comparison table

| Source claim (`migrate_v2.rs` @ main 094a06f1) | Original census (this window) |
| --- | --- |
| `checked_add(real_quote_reserves, post_complete_quote_in)` → Overflow | guard-shaped checked add at `0x78e18` |
| `checked_sub(fee)` (native), `checked_sub(quote_before)` | one guard-shaped checked sub at `0x786d0`; the second sub's shape unresolved here |
| `saturating_sub` ×2 in `init_pump_amm_boost_v2` | absent — consistent (`#[inline(never)]` helper, own window) |
| no division in `execute` | zero div/mod/mul64 sites |
| `error!(PumpError::…)` variants | no 6000+N immediates; bit-63 sentinel comparisons against variant indices 23/26 (hypothesis) |

## Limits

Static census of one window of the committed capture; nothing is executed and
no SBF build is performed. Window bounds from
`reconstruction/pump-main/prior-swarm/TARGETS-20261029.json`; similarity 0.201
quoted from `reconstruction/pump-main/lanes/callgraph-census`. The bit-63
error-ABI reading is a labeled hypothesis; the 0x1b5xxx constants and the
exact callee attribution are uninterpreted. This lane makes no equivalence or
security claim.
