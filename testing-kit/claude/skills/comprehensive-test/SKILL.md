---
name: comprehensive-test
description: Orchestrates 14 testing agents for complete SIOPV verification. Use when running full quality gates, before releases, or after major changes. Generates reports to ~/siopv/claude-verification-reports/.
disable-model-invocation: true
allowed-tools: Read, Write, Bash, Task
---

# Comprehensive Test

Runs all 14 verification agents in parallel phases for complete SIOPV quality gates.

## Anthropic Best Practices Applied (Feb 2026)

| Practice | Implementation |
|----------|----------------|
| **Model routing** | Haiku for simple, Sonnet for analysis |
| **Tool guidance** | Each prompt specifies TOOLS TO USE / DO NOT USE |
| **Effort budgets** | 5-80 tool calls per agent |
| **Parallel execution** | Foundation (5) and Phase (8) agents run in parallel |
| **Extended thinking** | Complex agents use REASONING steps |
| **LLM-as-judge** | Orchestrator verifies report format |
| **Checkpointing** | MANIFEST.md tracks status |
| **Progressive disclosure** | Agent prompts in separate files |

---

## Workflow

### Step 1: Setup (YOU must do directly)

```bash
TIMESTAMP=$(date +%Y-%m-%d-%H-%M)
mkdir -p ~/siopv/claude-verification-reports/$TIMESTAMP
```

Write MANIFEST using [templates/manifest.md](templates/manifest.md). Replace `{TIMESTAMP}` with actual value.

Save to: `~/siopv/claude-verification-reports/{TIMESTAMP}/MANIFEST.md`

---

### Step 2: Foundation Agents (Parallel)

Launch ALL 5 in parallel. Read each prompt file and pass to Task tool:

| Agent | Prompt File | Model | Subagent |
|-------|-------------|-------|----------|
| Best Practices | [prompts/best-practices.md](prompts/best-practices.md) | haiku | Explore |
| Security | [prompts/security.md](prompts/security.md) | sonnet | Explore |
| Hallucination | [prompts/hallucination.md](prompts/hallucination.md) | sonnet | Explore |
| Code Review | [prompts/code-review.md](prompts/code-review.md) | sonnet | Explore |
| Coverage | [prompts/coverage.md](prompts/coverage.md) | haiku | Bash |

**Invocation pattern:**
```
Task(subagent_type="[Subagent]", model="[Model]", prompt="[Content from prompt file with {TIMESTAMP} replaced]")
```

---

### Step 3: Phase Validators (Parallel)

Launch ALL 8 in parallel:

| Phase | Name | Status | Prompt |
|-------|------|--------|--------|
| 1 | Ingestion | Active | [prompts/phase-1-ingestion.md](prompts/phase-1-ingestion.md) |
| 2 | RAG/CRAG | Active | [prompts/phase-2-rag.md](prompts/phase-2-rag.md) |
| 3 | ML Classification | Active | [prompts/phase-3-ml.md](prompts/phase-3-ml.md) |
| 4 | Orchestration | Active | [prompts/phase-4-orchestration.md](prompts/phase-4-orchestration.md) |
| 5 | Authorization | Active | [prompts/phase-5-authorization.md](prompts/phase-5-authorization.md) |
| 6 | DLP | Stub | [prompts/phase-stub.md](prompts/phase-stub.md) |
| 7 | HITL | Stub | [prompts/phase-stub.md](prompts/phase-stub.md) |
| 8 | Output | Stub | [prompts/phase-stub.md](prompts/phase-stub.md) |

For stubs (6-8): Write stub report directly, no agent needed.

---

### Step 3.5: Verify Report Quality (LLM-as-Judge)

After agents complete, YOU verify each report:

1. Read each report file
2. Check: Has `**Status:** PASS` or `**Status:** FAIL`?
3. Check: Has `## Quality Gate` section?
4. Check: Non-empty and follows format?

If any check fails:
- Mark as ERROR in MANIFEST
- Note "Report format invalid"
- Continue with other agents

---

### Step 4: Generate Summary (YOU must do directly)

Read all 13 reports, extract status, generate summary using [templates/summary.md](templates/summary.md).

Save to: `~/siopv/claude-verification-reports/{TIMESTAMP}/00-COMPREHENSIVE-SUMMARY.md`

---

### Step 5: Finalize

1. Update MANIFEST.md status column (Pending → PASS/FAIL/ERROR)
2. Display summary to user
3. Report execution time

---

## Quality Gates

See [reference/quality-gates.md](reference/quality-gates.md) for threshold definitions.

---

## Anti-Autopilot Rules

1. **MANIFEST created by orchestrator** - Not delegated
2. **Agent prompts are self-contained** - No external file reading
3. **Output format embedded in prompt** - Templates for consistency
4. **Summary created by orchestrator** - Not delegated
5. **Explicit file paths** - Full paths, not relative
