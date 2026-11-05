---
title: "{{ .File.ContentBaseName | replaceRE "^\\d{4}-\\d{2}-\\d{2}-" "" | replace "-" " " | title }}"
date: {{ .Date }}
draft: true
slug: "{{ .File.ContentBaseName | replaceRE "^\\d{4}-\\d{2}-\\d{2}-" "" }}"
summary: ""
tags: []
---

