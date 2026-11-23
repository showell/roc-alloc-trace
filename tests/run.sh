#!/bin/sh
# The tests: roc-alloc-trace built, the copy pairs (tests/CopyPairs.roc)
# built in the release and the dev build, and each held to its check file;
# a planted count proved red; `where` naming the copying function; a
# threaded and a forking program refused; and the load base read right on
# many runs in a row. From the repository's root:
#
#   tests/run.sh               every test
#   ROC=/path/to/roc tests/run.sh
#
# It is tested with Roc 0.1.0_RC1 (ROC names it, else `roc` on the PATH)
# and needs a C compiler (CC, else cc). RUNS sets how many times the
# load-base test runs the program (200).

set -eu

cd "$(dirname "$0")/.."
CC=${CC:-cc}
RUNS=${RUNS:-200}
ROC=${ROC:-roc}
case "$("$ROC" version)" in
    *0.1.0_RC1*) ;;
    *) echo "tests/run.sh: $ROC is not Roc 0.1.0-RC1 ($("$ROC" version)); set ROC" >&2; exit 2 ;;
esac

failed=0
pass() { echo "PASS $1"; }
flunk() { echo "FAIL $1"; failed=$((failed + 1)); }

mkdir -p build/release build/dev
"$CC" -O2 -Wall -Wextra -Werror -o roc-alloc-trace roc-alloc-trace.c
pass "build: roc-alloc-trace with -Wall -Wextra -Werror"

# Roc builds an app from its own folder.
(cd tests && "$ROC" build CopyPairs.roc --opt=speed --output=../build/release/copy-pairs > ../build/roc-release.log 2>&1) || true
(cd tests && "$ROC" build CopyPairs.roc --opt=dev --output=../build/dev/copy-pairs > ../build/roc-dev.log 2>&1) || true
for b in release dev; do
    if [ ! -x "build/$b/copy-pairs" ] || grep -q '✗\|●' "build/roc-$b.log"; then
        cat "build/roc-$b.log"
        echo "tests/run.sh: the $b build of tests/CopyPairs.roc failed" >&2
        exit 2
    fi
done
pass "build: tests/CopyPairs.roc, release and dev"

for b in release dev; do
    if ./roc-alloc-trace check "tests/expected-$b.check" > "build/check-$b.out" 2>&1; then
        pass "check: the $b build holds tests/expected-$b.check ($(tail -n 1 "build/check-$b.out"))"
    else
        cat "build/check-$b.out"
        flunk "check: the $b build off tests/expected-$b.check"
    fi
done

# A plant on the data: set-or-crash, which writes in place, held to 1 an
# iteration. The check must go red, exit 1, and say which line moved.
sed 's/^set-or-crash 0 0/set-or-crash 1 0/' tests/expected-release.check > build/planted.check
if cmp -s tests/expected-release.check build/planted.check; then
    flunk "plant: the plant did not change the file"
elif ./roc-alloc-trace check build/planted.check > build/planted.out 2>&1; then
    flunk "plant: a count held at 1 that is 0 passed"
else
    code=$?
    if [ "$code" -eq 1 ] && grep -q '^- set-or-crash 1.00 0.00' build/planted.out && grep -q '^+ set-or-crash 0.00 0.00' build/planted.out \
        && grep -q '^1 off, of 8 controls' build/planted.out; then
        pass "plant: set-or-crash held to 1 is red, exit 1, with its diff"
    else
        cat build/planted.out
        flunk "plant: red for the wrong reason (exit $code)"
    fi
fi

# `where` names the copy: the builtin and the Roc function.
./roc-alloc-trace where -- build/dev/copy-pairs get-after-set 1000 '{N}' > build/where.out 2>&1 || true
if grep -q '^copy-pairs: list_set 1.00 of 8008 bytes from get_after_set' build/where.out \
    && grep -q '^1 copying sites over 1 runs' build/where.out; then
    pass "where: get-after-set copies through list_set from get_after_set"
else
    cat build/where.out
    flunk "where: get-after-set's copy not named"
fi
./roc-alloc-trace where -- build/dev/copy-pairs set-or-crash 1000 '{N}' > build/where-flat.out 2>&1 || true
if grep -q '^0 copying sites over 1 runs' build/where-flat.out; then
    pass "where: set-or-crash names no copy"
else
    cat build/where-flat.out
    flunk "where: set-or-crash named a copy"
fi

# No {N}: the program runs once and the totals are said.
./roc-alloc-trace count -- build/release/copy-pairs get-after-set 1000 5 > build/once.out 2>&1 || true
if grep -q 'ran once' build/once.out && grep -q '^allocs 7  reallocs 0' build/once.out; then
    pass "count: with no {N}, one run, 7 allocations for 5 copying writes"
else
    cat build/once.out
    flunk "count: a run with no {N}"
fi

# A thread or a process the program starts would run untraced into a
# breakpoint: refused, exit 2, never a hang.
"$CC" -O2 -pthread -o build/threads tests/threads.c
for what in thread fork; do
    arg=""
    [ "$what" = fork ] && arg=fork
    start=$(date +%s)
    if ./roc-alloc-trace count -- build/threads $arg > "build/$what.out" 2>&1; then
        flunk "refuse: a program that starts a $what was counted"
    else
        code=$?
        took=$(($(date +%s) - start))
        if [ "$took" -gt 5 ]; then
            flunk "refuse: the $what refusal took $took s: something waited on the stopped $what"
        elif [ "$code" -eq 2 ] && grep -q "started a $( [ "$what" = thread ] && echo thread || echo process )" "build/$what.out"; then
            pass "refuse: a program that starts a $what, exit 2"
        else
            cat "build/$what.out"
            flunk "refuse: a $what refused for the wrong reason (exit $code)"
        fi
    fi
done

# The load base, read many times: the kernel sometimes puts the vDSO below
# a static PIE, where a base read from the first mapping at file offset 0
# was [vvar]'s and every breakpoint missed (a count of 0). A long command
# line makes it likelier (about 2 execs in 100 with a thousand arguments,
# which the program ignores). Each run here must count the same.
extra=$(i=0; while [ "$i" -lt 999 ]; do printf 'a '; i=$((i + 1)); done)
want="allocs 12 22 1.00"
i=0
bad=0
while [ "$i" -lt "$RUNS" ]; do
    # shellcheck disable=SC2086
    got=$(./roc-alloc-trace count --small 10 --big 20 -- build/release/copy-pairs get-after-set 1000 '{N}' $extra 2>&1 | grep '^allocs' | tr -s ' ' || true)
    if [ "$got" != "$want" ]; then
        bad=$((bad + 1))
        echo "run $i: $got"
    fi
    i=$((i + 1))
done
if [ "$bad" -eq 0 ]; then
    pass "load base: $RUNS runs of get-after-set at 10 and 20, each 12 and 22 allocations"
else
    flunk "load base: $bad of $RUNS runs counted otherwise"
fi

if [ "$failed" -ne 0 ]; then
    echo "$failed failed"
    exit 1
fi
echo "every test passed"
