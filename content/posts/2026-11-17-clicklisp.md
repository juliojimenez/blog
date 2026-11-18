---
title: "clicklisp"
date: 2026-11-17T23:39:10-05:00
draft: false
slug: "clicklisp"
summary: "I wrote clicklisp, a Common Lisp query compiler and UDF runtime for ClickHouse that ships as one static binary: queries are Lisp lists that compile to SQL, rules and query libraries are plain Lisp files, and a SELECT can call a Lisp function. Here's what it does."
tags: ["clicklisp", "lisp", "security"]
---

SQL in a repository usually lives in strings. You can template and concatenate them, but you cannot compose two queries, or generate ten that differ in one clause, without writing a small text processor and hoping the quotes and parentheses still line up. Detection rules often end up the same way: a folder of SQL blobs, each with a name and a severity.

So I wrote [clicklisp](https://cl.clickhouse.com). You write a query as a Lisp list and it compiles to ClickHouse SQL, and the same program serves Lisp functions to ClickHouse as user-defined functions, which lets a `SELECT` call into Lisp. It is written in Common Lisp, compiled by [ECL](https://ecl.common-lisp.dev/) into one statically linked Linux binary under 4 MB, and is Apache 2.0 in the ClickHouse org. As for the name, ClickHouse starts with CL, and CL is what Lisp programmers call Common Lisp.

```
$ echo '(select ((as (count) c))
          :from events
          :where (and (= status 500)
                      (> ts (- (now) (interval 1 :hour))))
          :group-by (user)
          :order-by ((c :desc))
          :limit 10)' | clicklisp compile --pretty
SELECT count() AS c
FROM events
WHERE ((status = 500) AND (ts > (now() - INTERVAL 1 HOUR)))
GROUP BY user
ORDER BY c DESC
LIMIT 10
```

## What the Compiler Does

**Name and form translation.** `event-time` becomes `event_time`, `(to-start-of-hour ts)` becomes `toStartOfHour(ts)`, `(lambda (x) (* x 2))` becomes `x -> (x * 2)`, and `(< 1 x 10)` chains into `((1 < x) AND (x < 10))`. Under `:from`, `(s3 "https://..." "CSV")` is a table function.

**Escaping and typed parameters.** String literals are escaped, column and table names are validated or backtick-quoted, function names must be plain identifiers, and every infix expression gets its own parentheses. User input goes in as `(param town :string)`, which compiles to `{town:String}` and is bound by the server as a typed value. For anything the compiler has no form for, `(raw "...")` takes verbatim SQL.

## Rules and Query Libraries

`defrule` gives a query a name, a description, a severity and tags:

```lisp
(defrule ssh-bruteforce
    (:description "Hosts with more than 20 failed SSH logins in 10 minutes"
     :severity :high
     :tags (:t1110 :ssh))
  (select ((as source-ip ip) (as (count) attempts))
    :from auth-events
    :where (and (= event-type "ssh_login_failed")
                (> event-time (- (now) (interval 10 :minutes))))
    :group-by (source-ip)
    :having (> attempts 20)
    :order-by ((attempts :desc))))
```

A rule is compiled when its file loads, and a malformed one, with a misspelt clause or the wrong number of arguments, stops the load with exit code 1. `clicklisp rules sql --load rules.lisp --all` prints the SQL for each. `defquery` is `defrule` without the severity, for libraries that are not detections.

The file is plain Common Lisp and the queries in it are lists, so a macro can write them for you. This one stamps out a league table of UK districts per property type:

```lisp
(defmacro def-price-league (ptype)
  `(defquery ,(intern (format nil "TOP-~A-DISTRICTS" ptype))
       (:description ,(format nil "Priciest districts for ~(~A~) sales" ptype))
     (select (district (as (round (avg price)) avg-price))
       :from uk.uk-price-paid
       :where (= type ,(string-downcase (string ptype)))
       :group-by (district)
       :order-by ((avg-price :desc))
       :limit 10)))

(def-price-league flat)       ; => top-flat-districts
(def-price-league detached)   ; => top-detached-districts
```

The repository has four example libraries for ClickHouse's [public playground](https://sql.clickhouse.com), including six detection rules for a table of more than 11 billion public GitHub events, and the [site](https://cl.clickhouse.com/#demos) runs all four as live demos.

## Lisp From a SELECT

ClickHouse can call an external program as a function: it writes a block of rows to the program's stdin and reads one result back per row. clicklisp speaks that protocol for functions defined with `defudf`:

```lisp
(defudf shout (s)
  "Fraction of letters that are uppercase - a clickbait/shouting score."
  (if (or (null s) (zerop (length s)))
      0.0d0
      (let ((letters 0)
            (upper 0))
        (loop for char across s
              when (alpha-char-p char)
                do (incf letters)
                   (when (upper-case-p char) (incf upper)))
        (if (zerop letters)
            0.0d0
            (/ upper (float letters 1.0d0))))))
```

Save that as `text.lisp`, copy it and the static release binary into the server's `user_scripts_path`, and add this entry to a file whose name ends in `_function.xml` next to the server config ([full example](https://github.com/ClickHouse/clicklisp/blob/main/examples/clicklisp_function.xml)):

```xml
<function>
    <type>executable_pool</type>
    <name>clicklisp_shout</name>
    <command>clicklisp udf --fn shout --load user_scripts/text.lisp --watch user_scripts/text.lisp --chunked</command>
    <format>TabSeparated</format>
    <argument><type>String</type></argument>
    <return_type>Float64</return_type>
    <send_chunk_header>1</send_chunk_header>
</function>
```

Then call it:

```sql
SELECT clicklisp_shout('READ THIS now')
```

```
0.7272727272727273
```

**Hot patching.** With `--watch`, the process re-loads `text.lisp` when the file changes and keeps serving, and the next block of rows is answered by the new definition. The reload goes through ECL's bytecode compiler, which is part of the binary, and the server needs no C toolchain. If an edit fails to load, the error goes to the server log and the process carries on.

**Failing rows.** A row that makes the function signal an error is logged and comes back as NULL, or as the type's default when the return type is not Nullable. The rest of the block is still answered.

The binary also has `entropy` built in, the Shannon entropy of a string, and the `dga-domains` rule in the examples filters DNS lookups on it. That rule is a query compiled from Lisp that calls a Lisp function for each row.

## What Is Checked

The suite is 34 tests and 264 assertions on a homegrown harness, with no libraries to fetch. CI runs it on x86_64 and aarch64 with Ubuntu's ECL 21.2.1, and again under an ECL 26.5.5 built with AddressSanitizer and UBSan, which instrument the C that ECL generates from clicklisp's own source.

The limits I know of: it compiles `select` and unions of them, with no DDL or `INSERT`, and it checks the shape of a query but not the names in it, so a misspelt column still reaches the server. Window functions go through `(raw ...)`, and the UDF half needs a server you run yourself.

## Try It

```sh
git clone https://github.com/ClickHouse/clicklisp
cd clicklisp
brew install ecl    # or: apt install ecl
make
bin/clicklisp rules sql --load examples/analytics/uk-price-paid.lisp price-trend \
  | scripts/play.sh town=LONDON
```

That needs ECL and a C compiler and builds a binary for your machine. The last line runs an example query on the public playground and prints rows. Static Linux binaries for x86_64 and aarch64 are on the [releases page](https://github.com/ClickHouse/clicklisp/releases), currently 0.1.3. If you maintain a pile of ClickHouse queries that are mostly the same query, or you would rather keep detection rules as data than as strings, give clicklisp a look.
