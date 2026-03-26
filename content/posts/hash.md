---
title: "hash"
date: 2026-03-26
draft: false
summary: "I built hash, a POSIX-compliant shell with modern features baked in. Syntax highlighting, autosuggestions, Git-aware prompts — no plugins required."
tags: ["hash", "shell", "cli", "c"]
cover:
  image: "/images/hash-logo.png"
  alt: "hash logo"
  hiddenInSingle: false
---

Every shell makes you choose. Bash is everywhere but feels stuck in 1989. Zsh gets you modern features if you install a plugin manager, a framework, a theme, and then wait for your prompt to load. Fish gives you everything out of the box but breaks POSIX compatibility, so half your scripts and muscle memory stop working. Nushell reimagines everything from scratch, which is exciting until you need to run a `for` loop the way you've done it for twenty years.

I wanted a shell that didn't make me choose. So I built [hash](https://hash-shell.org).

hash is a POSIX-compliant command line interpreter written in C. It runs on Linux, macOS, and FreeBSD. It ships with syntax highlighting, autosuggestions, tab completion, persistent history, and Git-aware prompts — all built in, no plugins, no frameworks, no configuration rabbit holes. One install, and it works.

## What You Get Out of the Box

**Syntax highlighting** as you type. Commands, arguments, and operators are colored in real time so you catch typos before hitting enter.

**Autosuggestions** pulled from your history. Start typing and hash shows a dimmed completion inline. Accept it, ignore it, keep typing. It's the fish feature people love most, and it's here without leaving POSIX behind.

**Git-aware prompts** via a single `\g` escape in your `PS1`. It shows the current branch and status indicators — no shell functions to maintain, no plugin to configure. Just add `\g` to your prompt string and it works.

```bash
PS1='\e[\u@\h \W\g]\$ '
```

That gives you a color-coded prompt with username, hostname, working directory, Git branch with status, and a `$`/`#` indicator. The `\e` escape even changes color based on the exit code of your last command — green for success, red for failure.

**Tab completion** for commands, files, and directories. First press completes the common prefix. Second press shows all matches. Directory completions include trailing slashes so you can keep tabbing deeper.

**Persistent history** across sessions with all the controls you'd expect: `!!` to repeat the last command, `!n` by number, `!prefix` for pattern matching. History size is configurable via `HISTSIZE` and `HISTFILESIZE`. And if you prefix a command with a space, it never gets saved — useful when you're passing secrets on the command line and don't want them sitting in `~/.hash_history`.

**Full job control**: background processes with `&`, `jobs` to list them, `fg` and `bg` to manage them, `kill` to stop them.

## POSIX Compliance, Not POSIX Only

hash follows the POSIX standard. Your existing scripts work. Your `if/then/else`, `for`, `while`, `case` statements all work. Variable expansion, command substitution with `$()`, pipes, redirects (`>`, `>>`, `<`, `2>`, `&>`), logical operators (`&&`, `||`) — all of it works the way you expect.

But POSIX compliance doesn't mean POSIX limitations. hash layers modern interactive features on top of a standards-compliant foundation. You get the portability of POSIX with the experience of a next-generation shell.

Functions, aliases, and builtins like `cd`, `export`, `source`, `test`, `echo`, `alias`, and `history` are all here. The scripting surface area covers variables (`$?`, `$$`, `$0`–`$9`, `$#`, `$@`, `$*`), arithmetic expansion, and the `[` test command with file, string, and numeric operators.

## Simple Configuration

Three files. That's it.

- **`~/.hashrc`** — interactive settings, aliases, prompt customization
- **`~/.hash_profile`** — login shell environment setup
- **`~/.hash_logout`** — runs on login shell exit

No `.zshrc` that sources a framework that sources plugins that source themes. No `config.fish` with a different syntax than every other config file on your system. Just familiar dotfiles with familiar syntax.

## How hash Compares

| | hash | bash | zsh | fish | nushell |
|---|---|---|---|---|---|
| POSIX compliant | Yes | Yes | Mostly | No | No |
| Syntax highlighting | Built-in | Plugin | Plugin | Built-in | Built-in |
| Autosuggestions | Built-in | Plugin | Plugin | Built-in | Built-in |
| Git prompt | Built-in | Manual | Plugin | Built-in | Manual |
| Config complexity | 3 files | Moderate | High | Simple | Moderate |
| Written in | C | C | C | C++/Rust | Rust |

The pattern is clear. Bash and zsh require third-party plugins for features that should be standard in 2026. Fish and nushell include those features but break compatibility. hash is the only shell in this list that gives you both.

## Built for Quality

hash is compiled with `-Wall -Wextra -Werror`. The codebase is analyzed with SonarCloud, tested with Valgrind for memory safety, and runs through address and undefined behavior sanitizers. The test suite includes both unit tests (via the Unity framework) and integration tests. Fuzzing is part of the quality pipeline.

String operations use bounded variants throughout — no `strcpy`, no `strcat`. Input is sanitized. The code is written with the same discipline you'd expect from security-critical infrastructure.

## Install

**macOS (Homebrew):**
```
brew install juliojimenez/hash/hash-shell
```

**Debian/Ubuntu:**
```
echo "deb [trusted=yes] https://hash-shell.org/apt/ stable main" | sudo tee /etc/apt/sources.list.d/hash-shell.list
sudo apt update && sudo apt install hash-shell
```

**Docker:**
```
docker pull juliojimenez/hash-shell
```

**From source:**
```
git clone https://github.com/juliojimenez/hash.git
cd hash
make
sudo make install
```

Pre-compiled binaries are also available on the [releases page](https://github.com/juliojimenez/hash/releases) for Linux (x86_64, ARM64), FreeBSD (x86_64, ARM64), and macOS (Apple Silicon).

## Try It

hash is Apache 2.0 licensed and on [GitHub](https://github.com/juliojimenez/hash). If you've been meaning to upgrade from bash but don't want to give up POSIX compatibility or wrestle with plugin managers, hash might be what you're looking for.
