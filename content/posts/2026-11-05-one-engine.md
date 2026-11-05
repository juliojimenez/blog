---
title: "One engine"
date: 2026-11-05T12:45:28-05:00
draft: false
slug: "one-engine"
summary: "hash lost its line-oriented engine last night, 6,140 lines of it. By lunch today getopts, shift, local, the set options and a parser fuzzer had landed. The delete is what made the rest cheap."
tags: ["hash", "shell", "c"]
---

Last night I deleted 6,140 lines from [hash](https://hash-shell.org). By lunch today six more pull requests had landed: `getopts`, `shift`, `local`, the full set of `set` options, error messages that name what failed, and a fuzzer for the parser. Those two facts are related.

hash started with a line-oriented engine. Read a line, classify it, notice that it opens an `if` or a `for`, collect the body until the matching `fi` or `done`, run it. That carried the shell through v47. It also meant every construct was understood twice, once when the line was classified and again when its body ran, and some things never worked right: a brace group across several lines, a heredoc inside `eval`, the exit status of `if false; then :; fi`.

The replacement was five steps in under a week. A tokenizer with an arena allocator ([#293](https://github.com/juliojimenez/hash/pull/293)), a recursive-descent parser that builds a tree ([#294](https://github.com/juliojimenez/hash/pull/294)) and an executor that walks the tree over the existing back end ([#295](https://github.com/juliojimenez/hash/pull/295)) all landed on the same Friday. Then the step that made the rest safe: a switch ([#298](https://github.com/juliojimenez/hash/pull/298)). `HASH_ENGINE=ast` or `HASH_ENGINE=legacy` picked the engine, both stayed in the binary, and CI ran everything under each one. The 186 scripts of the smoosh POSIX suite, the 53 integration cases and the 31 unit test binaries passed on both. A diff script fed 209 programs to the two engines and compared stdout, stderr and exit status. Ten differed, each one accounted for: a known bug in the old engine, or an error message that now names the file.

Flipping the default was one line in `engine.c` ([#306](https://github.com/juliojimenez/hash/pull/306), shipped as v48). The old engine stayed one environment variable away for anyone who hit a regression. Step five ([#313](https://github.com/juliojimenez/hash/pull/313)) removed it: `script.c` went from 4,080 lines to 819, and `chain.c`, `pipeline.c` and `engine.c` went with it. `--engine` is now an unknown option like any other. 189 lines added, 6,140 removed. v49 went out with the delete, and v50 this morning with a fix for the `EXIT` trap under `-c` ([#316](https://github.com/juliojimenez/hash/pull/316)).

Then today. With one engine to teach, each gap in POSIX coverage was one change:

- **`getopts`** did not exist. A `while getopts` loop tried to run an external command, failed quietly and never iterated. Neither did `shift`, which every `getopts` loop ends with. Both are builtins now, checked against bash 5 line for line, `OPTIND` included ([#338](https://github.com/juliojimenez/hash/pull/338)).
- **`local`** did not exist either, so every variable a function set leaked into its caller. It runs on per-call scopes with dynamic scoping, as in dash and bash ([#339](https://github.com/juliojimenez/hash/pull/339)).
- **`set -x`** printed nothing, `set -C` clobbered, `set -n` ran the commands, and an unknown option was accepted in silence. The options live in one table now that `set`, `$-` and the command line all read, and `hash-shell -n script.sh` is a syntax check ([#340](https://github.com/juliojimenez/hash/pull/340)).
- **Error messages** say what failed. A command that could not run used to print `No such file or directory` with no command name and exit 1; it now names the command and exits 127 or 126, as POSIX says. Syntax errors name the file and line and exit 2, and `$LINENO` is a real number ([#336](https://github.com/juliojimenez/hash/pull/336), [#337](https://github.com/juliojimenez/hash/pull/337)).
- **Fuzzing** reached the tokenizer and the parser: AFL++ harnesses in CI, plus an ASan and UBSan sweep of every seed and all 186 smoosh scripts. Three thousand random mutations of that corpus, zero failures ([#341](https://github.com/juliojimenez/hash/pull/341)).

The integration suite went from 53 cases last Friday to 98 today.

None of this is a new lesson, but I keep relearning it. The second implementation is the cheap part. The parity test is the real work. The delete is the reward, and it pays out immediately: everything after it is written once. If you are replacing the core of something, build the switch first and keep both sides running until the numbers match.

v50 is on the [releases page](https://github.com/juliojimenez/hash/releases); today's builtins ship in the next one.
