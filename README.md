# roc-alloc-trace

Counts a Roc program's allocations, and finds the copies among them, in the
very executable you ship: no compiler fork, no relinking, no change to the
program. One C file, Linux x86-64.

The code here was written by Claude, an AI coding agent, under Steve
Howell's supervision. Point an agent at this repo to extend it.

## What it's for

Roc writes into a list in place when nothing else refers to it, and copies
the whole list otherwise. Nothing reports the copy: not the type checker,
not the compiler, not a warning at run time. These two loops differ by one
line, and the second copies its list on every write:

```roc
ys = xs.set(j, i) ?? crash "in range"    # in place
```

```roc
ys = xs.set(j, i) ?? xs
v = xs.get(j) ?? crash "in range"        # the old list read after the write: a copy
```

`roc-alloc-trace` runs a program at two sizes and says what one more
iteration allocates (0 for the first loop, 1 for the second), names the
builtin and the Roc function each copy came from, and holds a set of
programs to their counts in CI, so a change that turns an O(1) write into
an O(n) one fails a check instead of quietly slowing the program.

## Build

    cc -O2 -o roc-alloc-trace roc-alloc-trace.c

No other dependency: it reads the executable's symbol table and DWARF
itself. Tested with Roc 0.1.0_RC1, on the default platform (whose
allocator is `roc_alloc`, `roc_realloc` and `roc_dealloc`).

## The three modes

`{N}` in an argument is the iteration count: the program runs with N =
`--small` (1000) and again with N = `--big` (10000), and what one more
iteration costs is the difference divided by 9000. Your program reads its
iteration count from its arguments, wherever it likes, and `{N}` marks the
spot, so the tool needs no convention of yours (an environment variable, a
fixed position) and the command line you write is the one that runs. An
argument may hold `{N}` inside it (`--steps={N}`, a source text).

The program's own output goes to a file the tool keeps, and its last lines
are printed if it exits non-zero. Its standard input is `/dev/null`.

### `count`: allocations an iteration

    roc-alloc-trace count [--small N] [--big M] [--timeout S] -- PROGRAM ARG...

```
$ roc-alloc-trace count -- build/release/copy-pairs get-after-set 1000 {N}
                 N=1000      N=10000    an iteration
allocs             1002        10002            1.00
reallocs              0            0            0.00
deallocs           1002        10002            1.00
```

`get-after-set` writes into a list of 1,000 numbers N times, reading the
old list after each write: one copy a write. Its in-place twin,
`set-or-crash`, gives 2, 2 and 0.00.

With no `{N}` in the arguments the program runs once and the totals are
printed.

### `where`: which builtin copied, and from where

    roc-alloc-trace where [--small N] [--big M] [--timeout S] [--tsv FILE] -- PROGRAM ARG...
    roc-alloc-trace where [--tsv FILE] [--only PREFIX] CHECKFILE

```
$ roc-alloc-trace where -- build/dev/copy-pairs helper-length-after-set 1000 {N}
copy-pairs: 1.00 allocs and 0.00 reallocs an iteration in all
copy-pairs: list_set 1.00 of 8008 bytes from bump_length_after (CopyPairs:115)
1 copying sites over 1 runs; 186 builtins watched
```

In the dev build, a helper that reads its list's length after writing it
copies the list (8,008 bytes: 1,000 numbers and a header) through
`List.set`, at line 115; the release build specializes the helper and
writes in place.

A line a copying site: the writing builtin, what one more iteration
allocates through it (sites under 0.5 are left out, so the setup's
allocations drop out), the bytes each allocation asked for (a copy asks
for the whole list; a fresh small list, a few), the Roc function that
called the builtin, and its line when the line table has one. Build with
`roc build --debug` for names and lines. With a check file, every control
in it is run; `--tsv` writes the same rows as a table.

### `check`: hold counts in CI

    roc-alloc-trace check [--report] [--only PREFIX] CHECKFILE

A check file lists controls and the counts each is held to:

```
# The sizes, the tolerance an iteration and a run's limit in seconds.
small 1000
big 10000
slack 0.05
timeout 120
# A run that prints one of these words fails.
fail-if-printed overflowed

set-or-crash 0 0
  run build/release/copy-pairs set-or-crash 1000 {N}
get-after-set 1 0 the old list read after its write, so it copies
  run build/release/copy-pairs get-after-set 1000 {N}
```

A control is `<name> <allocs> <reallocs> [why]`: allocations and
reallocations an iteration (`1`, `2.03`), or `- -` for one held to
nothing. Its command line is indented below it:

- `run ARGV` with `{N}` in it;
- `small ARGV` and `big ARGV`, two command lines written out in full, for
  a program whose arguments grow with N in a way `{N}` can't say;
- `once ARGV` for a program with no loop, its counts the totals.

Arguments split on spaces as a shell splits them: `'...'` as written,
`"..."` with `\n`, `\t`, `\\`, `\"` and `\xHH`. A relative program path is
from the directory you run the tool in.

A check that passes prints a row a control and `0 off, of 8 controls`.
One that doesn't (here `set-or-crash`, which writes in place, held to 1):

```
$ roc-alloc-trace check build/planted.check
control                          allocs at 1000, 10000, an iteration   reallocs an iteration
set-or-crash                           2         2      0.00        0.00   OFF (held to 1.00 and 0.00)
get-after-set                       1002     10002      1.00        0.00   ok
...
1 off, of 8 controls, held to build/planted.check

what the file holds (-) and what ran (+), an iteration, allocs then reallocs:
build/planted.check:13
- set-or-crash 1.00 0.00
+ set-or-crash 0.00 0.00
```

It exits 0 when every control is within its slack, 1 when one is off (with
the diff above), and 2 when it couldn't measure (a run failed, a program
refused, a bad file). `--report` prints the table and holds nothing;
`--only` runs the controls whose names start so, as a report.

## How it works

The whole tool rests on one byte, 0xCC, x86's `int3` breakpoint
instruction, essentially unchanged since the original 8086 of 1978. It is
a single byte on purpose: the general `int n` takes two, and a debugger
must be able to overwrite the first byte of any instruction, however
short, without trampling the next one. Every debugger since works the same
way: save a byte, write 0xCC, take the trap, put the byte back, step once,
write it again. So does this one.

The program runs under `ptrace`, stopped at its exec before it runs a line.
The tool reads where the kernel loaded it (the entry point in
`/proc/PID/auxv` less the file's own), checks that the code there is the
file's, and writes an `int3` over the first byte of `roc_alloc`,
`roc_realloc` and `roc_dealloc`. Each stop is a call: counted, the byte put
back, one instruction stepped, the `int3` put back.

For `where`, each builtin in the symbol table (`roc_builtins_list_set`,
`list.*`, `str.*`, the dev build's `roc_desc_list_op`) gets a breakpoint
too. At a function's first instruction the return address is on top of the
stack. A builtin entered from a Roc procedure (a `roc__p...` symbol) is
remembered with that call site and the return addresses the frame pointers
lead to above it. An allocation whose own return address is in no Roc
procedure was made by builtin code, and is put down to the last builtin
entered. The size comes from `rdi` (`roc_alloc`'s size) or `rsi`
(`roc_realloc`'s new size). Names come from DWARF's `DW_AT_name` beside
each procedure's linkage name, lines from `.debug_line`, both read by the
tool.

Roc hides whether a write copied; the tool listens at the door of the
builtin that decides.

## Limits

- **Linux x86-64 only.** The breakpoints, the registers and the ELF reader
  are that platform's.
- **Single-threaded programs only.** A thread the program started would
  not be traced, and would stop for good at its first breakpoint, so the
  tool refuses a program that starts a thread (or a process, or execs
  another program): exit 2, with the reason, never a hang.
- **Builtins must stay named functions.** True of Roc 0.1.0_RC1 in every
  build we checked. If a future Roc inlines the copy path into your code,
  `where` sees the allocation as made by Roc code and names no copy; the
  counts in `count` and `check` are unaffected.
- **Release builds attribute less precisely.** Optimized code keeps no
  frame pointers, so the walk above the builtin's caller stops early, and a
  copy may be put down to the Builtin module's own Roc code or the nearest
  procedure. Dev builds keep them.
- **"The last builtin entered" is a heuristic.** Right for a copy inside
  `List.set`; a builtin that calls another may be credited to the outer
  one.
- **Each counted call stops the program**, about 80 µs a call, so a
  program that allocates millions of times takes minutes.

## Tests

    tests/run.sh

builds the tool and `tests/CopyPairs.roc` (four pairs of loops, each pair
differing in one line) in the release and the dev build, holds each to
`tests/expected-release.check` and `tests/expected-dev.check`, proves the
check can see by planting a wrong count and watching it go red, checks
`where` names the copy, checks a threaded and a forking program are
refused, and runs one control 200 times to hold the load base steady. Set
`ROC` to a Roc 0.1.0_RC1 compiler if `roc` on the PATH isn't one.

## Users

[roc-apps](https://github.com/showell/roc-apps) holds its interpreters'
controls and its copy shapes to their counts with it, in three builds.

## License

UPL 1.0; see LICENSE.
