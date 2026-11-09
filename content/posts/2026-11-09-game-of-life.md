---
title: "Game of Life"
date: 2026-11-09T03:40:52-05:00
draft: false
slug: "game-of-life"
summary: "I wrote Conway's Game of Life in Common Lisp: a library for the REPL, a terminal viewer and a headless command line on one sparse engine, with any Life-like rule, three topologies, RLE and plaintext files, and a suite that passes on SBCL, ECL and CCL. Here's what it does."
tags: ["game-of-life", "lisp", "cli"]
---

The textbook Game of Life is a two-dimensional array. You pick a size, the edges wrap or kill whatever reaches them, and every generation costs the whole grid whether five cells are alive or five thousand. I wrote [Game of Life](https://github.com/juliojimenez/game-of-life) in Common Lisp with no grid. A world is a hash table of live cells, so the plane is unbounded and a step costs in proportion to the population.

It is one engine behind three faces: a library you drive from the REPL, a terminal viewer, and a headless command line. No Quicklisp, no third-party libraries, no FFI; `game-of-life.asd` and `src/` are the whole thing. It is Apache 2.0.

## What It Does

- **Any Life-like rule.** `B3/S23` is the default. `--rule` and `parse-rule` also take `B36/S23`, `b3s23`, the old `23/3` order, Golly's `B3/S23:T100,100`, and eleven names from `highlife` and `seeds` to `day-and-night` and `maze`.
- **Three topologies.** The plane has no edges. A torus wraps: set a cell at (-1, -1) on a 40 by 20 torus and it lands at (39, 19). A box treats everything outside it as dead. One `step-world` serves all three.
- **Patterns in and out.** 24 built-in patterns: seven still lifes, nine oscillators, four spaceships, three methuselahs and the Gosper glider gun. RLE as Golly reads it and plaintext `.cells` go both ways, Life 1.06 is read, and the format is detected from the content.
- **A terminal viewer.** `bin/life gosper-glider-gun` draws with half blocks, two cell rows per character row, so cells look square. The status line shows generation, population, rule, topology, speed and seed. Space pauses, `n` steps, `+` and `-` run from 1 to 120 generations a second, `f` follows the live cells across the plane, `q` quits. It runs on the alternate screen, so your terminal is as you left it afterwards; `--ascii` is for a terminal without UTF-8.
- **A headless mode.** `bin/life r-pentomino --headless -g 1103` prints `R-pentomino: generation 1103, population 116`. The run ends at the generation limit, when the world repeats with a period up to 64, or when it dies out: Diehard is extinct at generation 130, a glider on an 8 by 8 torus has period 32. `--write` saves the final world as RLE.
- **Soups you can replay.** `bin/life` alone is a random soup on a torus the size of your terminal. The generator is splitmix64 in integer arithmetic, so the seed in the status line replays the same soup with `-s` on every implementation.

At the REPL the same engine looks like this; `simulate` returns `:extinct`, `:periodic` with the period, or `:limit`:

```lisp
(defparameter w (life:make-world))   ; #<WORLD plane gen 0 pop 0>
(life:place w "glider")              ; #<WORLD plane gen 0 pop 5>
(life:step-world w 4)                ; #<WORLD plane gen 4 pop 5>
(life:live-cells w)                  ; ((1 . 0) (2 . 1) (0 . 2) (1 . 2) (2 . 2))
(life:simulate (life:place (life:make-world :topology :torus :width 8 :height 8) "glider"))
                                     ; :PERIODIC, 32
```

## How It Is Built

A cell is `x` and `y` packed into one 60-bit non-negative fixnum, 60 because CCL's fixnums are 60 bits wide, SBCL's 62 and ECL's 61, so the `eql` hash tables never see a bignum and never cons a key. A world owns two tables: one pass over the live cells writes neighbor counts and an alive bit into a scratch table, one pass over the scratch table rewrites the live set. Nothing is allocated per generation except what the tables grow into, and a glider on the infinite plane costs the same as one on a 10 by 10 torus.

The terminal work goes through `stty`, via `sh` with SIGTTOU ignored: CCL's `run-program` puts the child in its own process group, so a `stty` that changes the terminal is stopped by SIGTTOU and the call waits forever. That and every other implementation difference sit in `src/compat.lisp`, the only file with reader conditionals.

## What Is Checked

The suite is 71 tests and 1,988 checks, with no failures on SBCL 2.6.10, ECL 26.5 and CCL 1.14. Every built-in pattern is an oracle: still lifes do not change, oscillators return exactly at their period and not a generation before, spaceships translate, the methuselahs hit their numbers, the gun emits a glider every 30 generations. The slow one, Acorn settling at 633 cells on generation 5206, runs under `LIFE_LONG_TESTS=1` and in CI. The tests are longer than the program: 2,435 lines against 2,203.

`make build` is a forced compile that fails on any compiler warning. CI runs it, the suite and the executable on Ubuntu and macOS, then a Python smoke test that gives `bin/life` a real pseudo-terminal, presses `q` and space, checks the escape sequences and their order, and checks that the terminal is back in canonical, echoing mode afterwards. ECL is its own job.

## Try It

```sh
git clone https://github.com/juliojimenez/game-of-life
cd game-of-life
make bin
bin/life gosper-glider-gun
```

You need SBCL, `make` and `stty`. It is 0.1.0, and `DESIGN.md` is the specification and wins over the code; there is no Hashlife yet. If you want a Life you can poke at from a REPL, or a quick way to check that a pattern has the period you think it has, give it a run.
