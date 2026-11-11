---
title: "Where POSIX leaves room"
date: 2026-11-11T04:10:01-05:00
draft: false
slug: "where-posix-leaves-room"
summary: "I ran 32 one-liners through hash and bash and diffed the output. v54 fixes what the diff found: the option terminator on every builtin, bash's type options, and what trap lists inside a subshell. The man page and the book are generated from the shell's own help table now, with a check in CI that keeps them that way."
tags: ["hash", "shell"]
---

The cheapest compatibility test I know is to run the same one-liner through two shells and diff the output. I ran 32 of them through `hash-shell -c` and `bash -c`. The diff turned up three things hash got wrong. Two sit in corners where POSIX leaves the choice to the shell and bash scripts have settled on one answer; the third is a design hash picked and I never finished. All three are fixed in v54, which went out last night, along with a gap of a different kind: the man page described 15 of hash's 44 builtins.

## The Option Terminator and `type`

Thirteen builtins rejected `--`. `type -- echo` printed `--: not found` and then answered anyway, `kill -- -999999` complained about an invalid signal, `eval -- 'echo hi'` tried to run `--` as a command, and `exit -- 3` came back with `numeric argument required`. POSIX gives every utility that takes operands the `--` terminator, and four of the 13 were regular builtins that have to take it. The standard lets the special builtins skip it, but bash takes `--` on all of them and scripts written for bash use it, so hash takes it everywhere now. One helper in `builtins.c` finds the first operand for each of the 13, and `kill -- -PGID` reaches the pid parser, which already understood negative numbers ([#428](https://github.com/juliojimenez/hash/pull/428)).

`type` had the same shape of problem. POSIX gives it no options at all. bash gives it five, and scripts use `type -t` in exactly the places that decide whether something is safe to call. hash answered `-t: not found`. It takes `-t`, `-p`, `-P`, `-a` and `-f` with bash's meanings now ([#430](https://github.com/juliojimenez/hash/pull/430)):

```
$ type -t echo if ls
builtin
keyword
file
$ type -P echo
/bin/echo
$ type -a echo
echo is a shell builtin
echo is /bin/echo
```

The old `type` also checked builtins before functions, so a function named `echo` was reported as both. It now resolves a name the way the shell does, alias, keyword, function, builtin, file, and reports the first match unless `-a` asks for all of them. With `--` fixed, the probe differed from bash on five lines, none about `--`. Two of the five were `type -t` and the trap listing.

## What `trap` Lists in a Subshell

POSIX allows two designs here. bash and dash reset the traps when a subshell starts and list the current ones, with a lexical check so that `$(trap)` still shows the parent's. ksh93 lists the traps that were in effect when the subshell was entered until a trap command runs there, and the current traps from then on. hash follows ksh93, and I never finished the job: the copies it kept for the listing lived as long as the subshell, so `trap` kept showing traps that were no longer in effect.

```
trap 'echo t' USR1
(trap - USR1; trap)           # listed the trap it had just removed; now nothing
(trap 'echo u' USR2; trap)    # listed USR1 and USR2; now USR2 only
s=$(trap - USR1; trap)        # held the removed trap; now empty
```

The last line is the idiom for saving traps to put back later with `eval "$s"`, and hash was handing back a trap the script had just removed. A subshell now saves the traps in effect at entry and drops those copies on the first trap command with operands ([#431](https://github.com/juliojimenez/hash/pull/431)). Ten shapes probed against ksh93 all agree now.

## One Text for the Builtins

The man page described 15 of the 44 builtins and none of the options added since v47. The book had seven chapter copies that nothing built, and two of my own pull requests edited a copy instead of the live page, so `ulimit` and `pwd -L/-P` never reached the site.

Those pages are generated now. `scripts/docs-parity.py` reads the builtin table in `src/builtins.c`, the name, synopsis and description that `help` prints, and writes the SHELL BUILTIN COMMANDS section of the man page and a book page with one heading per builtin. `make check-docs` fails when either differs from the table or when the quick reference has no row for a builtin, and the Tests workflow runs it on every push ([#432](https://github.com/juliojimenez/hash/pull/432)). `help trap`, `man hash-shell` and the [builtins page](https://hash-shell.org/reference/builtins.html) say the same thing, and they cannot drift apart without a red build. The rest of the man page was filled in by hand from the book: `$'...'`, here-documents, `>|`, the prompt escapes, vi mode, the login files.

Each fix landed with an exec test for the shapes it changed and new test.sh cases. Behind v54: 29 unit binaries with 612 tests, test.sh at 347 of 347 on macOS and 353 of 353 on Linux, smoosh at 185 of 186 with the one miss being the known `builtin.trap.subshell.false.exit`, modernish at 389 tests with no unexpected failures, and ASan, UBSan, LeakSanitizer and ThreadSanitizer clean.

v54 is on the [releases page](https://github.com/juliojimenez/hash/releases) for Linux, macOS and FreeBSD, and the Debian, Docker and Homebrew builds come off the same tag. If you have been feeding bash scripts to hash and hitting `--: not found`, this is the release to upgrade to.
