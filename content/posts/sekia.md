---
title: "sekia.ai"
date: 2026-03-18
draft: false
summary: "I built sekia, an open-source multi-agent event bus for security automation. Here's what it does and the three workflows that have had the biggest impact on my day-to-day work."
tags: ["sekia", "security", "automation", "go"]
cover:
  image: "/images/sekia-logo.png"
  alt: "sekia logo"
  hiddenInSingle: false
---

I spend my days leading cloud infrastructure security across AWS, GCP, and Azure. That means a constant stream of alerts, access requests, vulnerability findings, and cross-platform noise that demands attention. Most of it is repetitive. Most of it follows patterns. And most of it was eating hours I should have been spending on actual security engineering.

So I built [sekia](https://sekia.ai), an open-source multi-agent event bus that connects the tools I already use and lets me automate workflows with Lua scripts and built-in AI. It ties together GitHub, Slack, Linear, Gmail, and Google Calendar over an embedded NATS message bus. Seven small Go binaries, zero external dependencies, one `brew install` to get started.

This post covers what sekia does, how it handles security, and the three workflows that have had the biggest impact on my day-to-day work.

## What sekia Actually Is

sekia is a daemon (`sekiad`) with an embedded NATS server and JetStream for durable messaging. Lightweight agents (`sekia-github`, `sekia-slack`, `sekia-linear`, `sekia-google`) connect to the bus, publish events from external services, and execute commands dispatched by Lua workflows. A CLI (`sekiactl`) and an optional MCP server (`sekia-mcp`) round things out.

The architecture is simple: agents emit events, Lua scripts react to them, and scripts can send commands back to any connected agent. Everything flows through NATS subjects like `sekia.events.github` or `sekia.commands.slack-agent`. Agents heartbeat every 30 seconds, auto-register on connect, and support named instances for multi-tenancy.

The Lua API is intentionally small. `sekia.on()` subscribes to event patterns. `sekia.command()` talks to agents. `sekia.ai()` and `sekia.ai_json()` call an LLM (Claude by default) directly from your workflow. `sekia.schedule()` runs handlers on a timer for autonomous agent behavior. `sekia.conversation()` gives you multi-turn state for threaded interactions. That's the whole surface area, and it covers a surprising amount of ground.

Workflows live in `~/.config/sekia/workflows/` as plain `.lua` files. Hot-reload is on by default, so editing a file picks up changes immediately. No deploys, no containers, no CI pipeline for a config change.

## Security by Design

I built sekia with the same mindset I bring to production infrastructure. Secrets never sit in plaintext configs. sekia supports three encryption backends that can be mixed in the same TOML file: `ENC[...]` for local age keypair encryption, `KMS[...]` for AWS KMS, and `ASM[...]` for AWS Secrets Manager. You pick the backend that fits your threat model. Age keys can live off-machine via `SEKIA_AGE_KEY` or `SEKIA_AGE_KEY_FILE`. AWS backends use the standard SDK credential chain.

Lua workflows run in a sandboxed VM. Only `base`, `table`, `string`, and `math` are available. No `os`, no `io`, no `debug`, no `dofile`, no `load`. A workflow cannot touch the filesystem or execute arbitrary commands on the host.

For supply-chain integrity, sekia supports workflow verification. Enable `workflows.verify_integrity` and each `.lua` file is checked against a SHA256 manifest before loading. `sekiactl workflows sign` generates the manifest. Tampered or unsigned workflows do not execute. When hot-reload is active, updating the manifest triggers a full reload.

The web dashboard (htmx + SSE, embedded in the binary) ships with `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, and `Strict-Transport-Security` headers on every response. SSE connections are capped at 50 to prevent resource exhaustion. All state-changing requests require CSRF protection via double-submit cookie.

The NATS bus listens on `127.0.0.1:7600` by default and the HTTP API runs over a Unix socket. Nothing is exposed to the network unless you explicitly configure it.

## Workflow 1: Auto-Remediating Security Operations Issues

The workflow that saves me the most time handles the triage and remediation loop for security findings. Vulnerability scanners like Wiz generate a constant stream of issues that land in our secops repo. Most follow well-known patterns: a misconfigured S3 bucket policy, an overly permissive IAM role, an unencrypted resource.

With sekia, I have a scheduled workflow that periodically reviews open issues, classifies them with `sekia.ai_json()`, and takes action based on severity and type. For findings that match known remediation patterns, the workflow opens a PR with the Terraform fix directly. For everything else, it triages into the right priority bucket in Linear and pings the on-call channel in Slack.

```lua
sekia.schedule(300, function()
    local result, err = sekia.ai_json(
        "Review these security findings and classify each by severity "
        .. "and whether auto-remediation is possible:\n\n" .. findings,
        { system = sekia.skill("secops-triage") }
    )
    if err then return end

    for _, finding in ipairs(result.findings or {}) do
        if finding.auto_remediate then
            sekia.command("github-agent", "create_comment", {
                owner = "myorg", repo = "secops",
                number = finding.issue_number,
                body = "Auto-remediation PR opened. Review and merge.",
            })
        else
            sekia.command("linear-agent", "create_issue", {
                team_id = SECURITY_TEAM_ID,
                title = "[" .. finding.severity .. "] " .. finding.title,
                description = finding.summary .. "\n\nGitHub: " .. finding.url,
            })
        end
    end
end)
```

The key here is the skill system. The `secops-triage` skill is a markdown file that encodes my team's remediation playbook: what constitutes auto-remediatable, what the Terraform patterns look like, and how to prioritize. The AI does not freelance. It follows documented procedures.

## Workflow 2: Cleaning Up My Gmail Inbox

Email is a tax on security engineers. Vendor alerts, compliance notifications, access request confirmations, certificate expiry warnings. Important signal buried under noise.

The Google agent polls Gmail and publishes `gmail.message.received` events. My cleanup workflow uses AI to classify each message into one of a few buckets: actionable (keep in inbox), informational (archive with a label), or noise (archive immediately). Actionable messages that relate to security operations get forwarded to the appropriate Slack channel as well.

```lua
sekia.on("sekia.events.google", function(event)
    if event.type ~= "gmail.message.received" then return end

    local result, err = sekia.ai_json(
        "Classify this email. Respond with action and reason.\n\n"
        .. "From: " .. event.payload.from .. "\n"
        .. "Subject: " .. event.payload.subject .. "\n"
        .. "Body: " .. event.payload.body,
        { system = "Classify as: actionable, informational, or noise. "
          .. "If security-related and actionable, set security=true." }
    )
    if err then return end

    if result.action == "noise" then
        sekia.command("google-agent", "archive", {
            message_id = event.payload.id,
        })
    elseif result.action == "informational" then
        sekia.command("google-agent", "add_label", {
            message_id = event.payload.id, label = "auto/informational",
        })
        sekia.command("google-agent", "archive", {
            message_id = event.payload.id,
        })
    end

    if result.security then
        sekia.command("slack-agent", "send_message", {
            channel = C_SECURITY,
            text = "Flagged email from " .. event.payload.from
                .. ": " .. event.payload.subject,
        })
    end
end)
```

In a typical week this archives 60-70% of my incoming mail automatically and surfaces the security-relevant messages where I actually see them.

## Workflow 3: Daily Email Summaries to Slack

The third workflow ties things together. Every morning at 8am, a scheduled handler scans the last 24 hours of Gmail activity, builds a digest with AI, and posts it to my Slack DM. No more opening Gmail to figure out what happened overnight.

```lua
sekia.schedule(86400, function()
    local conv = sekia.conversation("internal", "daily-digest", "singleton")

    local summary, err = conv:reply(
        "Summarize the key emails from the last 24 hours. "
        .. "Group by: security alerts, access requests, vendor updates, "
        .. "and everything else. Keep it concise."
    )
    if err then return end

    sekia.command("slack-agent", "send_message", {
        channel = MY_DM_CHANNEL,
        text = summary,
    })
end)
```

The conversation API here is a nice touch. Because it maintains multi-turn state, I can follow up in Slack (via the `slack.mention` event) and ask clarifying questions about specific emails. The context carries over.

## Getting Started

sekia installs in one line:

```
brew install sekia-ai/tap/sekia
```

Then install whichever agents you need, set your tokens as environment variables, drop a `.lua` file in the workflows directory, and run `sekiad`. The [documentation](https://sekia.ai/docs/) walks through setup for each agent.

The project is Apache 2.0 licensed and on [GitHub](https://github.com/sekia-ai/sekia). Contributions, feedback, and workflow ideas are welcome. If you work in security and you are tired of context-switching between six different tools to do the same repetitive tasks, give sekia a look.
