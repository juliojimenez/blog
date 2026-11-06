---
title: "No OpenSSL"
date: 2026-11-06T12:52:58-05:00
draft: false
slug: "no-openssl"
summary: "habichuela, my Common Lisp repository-a-day site, could not make an HTTPS request from Lisp on a current Mac: OpenSSL 4 removed a function cl+ssl calls. The fix was not a newer cl+ssl. It was no OpenSSL at all."
tags: ["habichuela", "lisp"]
---

[habichuela](https://habichue.la) is a small site I started this week: one Common Lisp repository a day. A GitHub Actions job picks a project from Quicklisp or from a search of GitHub, GitLab and Codeberg, records its stars, license, tests and ASDF systems, and rebuilds a static archive with an Atom feed. It is written in Common Lisp, runs on SBCL, and has no server. The pool is 2,283 projects.

On my Mac it could not make an HTTPS request from Lisp. Every Lisp HTTP client, dexador and drakma included, depends on cl+ssl, and the released cl+ssl calls `ASN1_STRING_data`. OpenSSL 4 removed that function when it made `ASN1_STRING` opaque, and Homebrew's `openssl` now points at 4.x. Every request died the same way:

```
The alien function "ASN1_STRING_data" is undefined.
```

Ubuntu runners have OpenSSL 3 and never noticed ([#7](https://github.com/juliojimenez/habichuela/issues/7)).

The first fix was a detour: drive `curl` from Lisp. It worked, it dropped about twenty transitive dependencies, and it left a Lisp program shelling out for its HTTP, which is the kind of thing you accept on Wednesday and resent by Thursday.

The real fix exists upstream, too. fukamachi, who wrote dexador, has an open cl+ssl pull request that switches to `ASN1_STRING_get0_data`, the replacement OpenSSL has shipped since 1.1.0 ([cl-plus-ssl#202](https://github.com/cl-plus-ssl/cl-plus-ssl/pull/202)). I checked out the branch and confirmed it: with it in place, dexador reaches api.github.com, codeberg.org and raw.githubusercontent.com with hostname verification, on macOS arm64 with Homebrew openssl@4 4.1.0 and SBCL 2.6.9. The pull request has been open since October 8. Waiting on a merge and then on a dist release was not a plan.

The way out came from the build system. I moved dependency management from a date-pinned Quicklisp dist to [ocicl](https://github.com/ocicl/ocicl) ([#17](https://github.com/juliojimenez/habichuela/pull/17)): 47 systems locked to sha256 digests in `ocicl.csv`, fetched over HTTPS from ghcr.io. qlot had been the obvious choice, and qlot is broken on macOS by the same cl+ssl bug. ocicl was not, because its own TLS is [pure-tls](https://github.com/atgreen/pure-tls), a TLS 1.3 implementation in Common Lisp. No OpenSSL binding anywhere in it. If a package manager could do HTTPS that way, so could my program.

So HTTP is a Lisp client again ([#18](https://github.com/juliojimenez/habichuela/pull/18)). `http-get` calls dexador, and dexador's TLS comes from pure-tls. The trick is keeping cl+ssl out of the image, because dexador depends on it by name:

```lisp
(defsystem "habichuela"
  ;; dexador asks for cl+ssl, the OpenSSL binding. pure-tls provides the same API in
  ;; pure Lisp; loading its compatibility layer before anything else and marking cl+ssl
  ;; as already loaded (below) keeps OpenSSL out of the build entirely.
  :defsystem-depends-on ("pure-tls/cl+ssl-compat")
  :depends-on ("alexandria" "babel" "com.inuoe.jzon" "dexador" "local-time" "spinneret")
  ...)

(asdf:register-immutable-system "cl+ssl")
```

The compat system loads first and exports every cl+ssl symbol dexador uses. The immutable registration tells ASDF that cl+ssl is already provided, so it never plans the real one. The lockfile went from 47 systems to 89 and contains no OpenSSL binding. The binary grew to 73 MB.

A TLS stack I did not write gets tested against bad certificates before it touches anything:

| Target | Result |
|---|---|
| Local `openssl s_server`, self-signed certificate, TLS 1.3 | refused: certificate not trusted |
| GitHub by bare IP, 140.82.112.3 | refused: IP does not match any SAN |
| expired-rsa-dv.ssl.com | refused: certificate verification failed |
| revoked-rsa-dv.ssl.com | refused: certificate verification failed |
| api.github.com | 200 |

badssl.com was no use: it only speaks TLS 1.2, which pure-tls does not. On macOS, trust goes through the Security framework, the only foreign libraries left in the image. On Linux it reads the system CA bundle, exercised by a green dry run of the workflow on Ubuntu. One cosmetic wart: pure-tls warns once per process that 1 of the 128 certificates in `/etc/ssl/cert.pem` has a non-positive serial number and was skipped. That is Apple's bundle, not mine.

The curl layer is gone, and so is the whole class of failure. No OpenSSL version can break this program, because none is loaded. That is a better place to be than waiting for the right version.

habichuela is Apache 2.0 and on [GitHub](https://github.com/juliojimenez/habichuela). Today's pick is at [habichue.la](https://habichue.la).
