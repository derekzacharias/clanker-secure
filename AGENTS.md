# Agent Operating Rules

Purpose: Agent behavior, constraints, and decision rules

## Source of Truth
All functional requirements are defined in:
- docs/requirements.md

Agents MUST NOT invent features or remove scope without updating requirements.md.

## Core Principles
- Prioritize risk over raw CVE counts
- Prefer authenticated scanning when credentials exist
- Optimize for low noise and high signal
- Provide remediation context for all findings
- Design API-first and automation-first

## Guardrails
- Do not implement features that are not traceable to requirements.md
- Do not trade accuracy for scan speed
- Do not generate unauthenticated findings when authenticated access is available

## Decision Heuristics
When tradeoffs exist:
- Accuracy over coverage
- Explainability over opaque scoring
- Extensibility over short-term delivery
- Standards over proprietary formats
