# Testing Kit Design

## Purpose

Provide SIOPV with standalone, portable verification infrastructure that can be:
1. Copied in for testing
2. Run comprehensive quality gates
3. Removed after testing, leaving SIOPV clean

## Anthropic Best Practices Applied (Feb 2026)

Based on:
- [Multi-Agent Research System](https://www.anthropic.com/engineering/multi-agent-research-system)
- [Claude Agent SDK Guide](https://claude.com/blog/building-agents-with-the-claude-agent-sdk)
- [Claude Code Subagents Docs](https://code.claude.com/docs/en/sub-agents)
- [Skill Authoring Best Practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices)

### Core Patterns

| Principle | Implementation |
|-----------|----------------|
| "One agent = one task" | 14 focused agents, each with single responsibility |
| "Orchestrator coordinates" | `/comprehensive-test` skill invokes agents |
| "Agents save own reports" | Each agent writes to numbered report file |
| "Parallel when independent" | Foundation and phase agents run in parallel |

### Advanced Patterns (2026)

| Practice | Implementation |
|----------|----------------|
| **Model routing** | Haiku for simple tasks, Sonnet for complex analysis |
| **Tool guidance** | Each prompt specifies TOOLS TO USE / DO NOT USE |
| **Effort budgets** | Max tool calls defined per agent (5-80 range) |
| **Parallel tool calls** | Agents encouraged to make simultaneous calls |
| **Extended thinking** | Complex agents use REASONING step-by-step |
| **LLM-as-judge** | Orchestrator verifies report format before accepting |
| **Checkpointing** | MANIFEST.md tracks status for resumable execution |
| **Progressive disclosure** | SKILL.md < 500 lines, prompts in separate files |

### Anti-Autopilot Guard-Rails

| Guard-Rail | Purpose |
|------------|---------|
| Self-contained prompts | No "read external file" instructions |
| Embedded output format | Exact format in prompt, not referenced |
| Explicit tool restrictions | DO NOT USE prevents wrong tool usage |
| Effort limits | Prevents runaway agents |
| Format verification | Rejects malformed reports |

### File Structure Best Practices

| Practice | Implementation |
|----------|----------------|
| YAML frontmatter | All skills have name, description, disable-model-invocation |
| SKILL.md < 500 lines | Main file is 124 lines, prompts in separate files |
| Progressive disclosure | Reference files loaded on-demand |
| One level deep refs | All refs from SKILL.md, no nested chains |

## Architecture Decisions

### 1. Portable Design
- Testing kit lives in `~/siopv/testing-kit/`
- Copied to `.claude/` only during testing
- Removed after, leaving SIOPV exportable

### 2. Separate Report Location
- Reports saved to `~/siopv/claude-verification-reports/` (permanent)
- Not inside `.claude/` (temporary)
- Git-ignored but preserves history

### 3. Skill Structure (Restructured Feb 2026)
```
skills/comprehensive-test/
├── SKILL.md              # Workflow + navigation (124 lines)
├── prompts/              # Agent prompts (self-contained)
│   ├── best-practices.md
│   ├── security.md
│   ├── hallucination.md
│   ├── code-review.md
│   ├── coverage.md
│   ├── phase-1-ingestion.md
│   ├── phase-2-rag.md
│   ├── phase-3-ml.md
│   ├── phase-4-orchestration.md
│   ├── phase-5-authorization.md
│   └── phase-stub.md
├── templates/            # Output templates
│   ├── manifest.md
│   └── summary.md
└── reference/            # Threshold definitions
    └── quality-gates.md
```

### 4. Parallelization Strategy
- Foundation agents: All 5 run in parallel (independent)
- Phase validators: All 8 run in parallel (independent)
- Comprehensive report: Runs last (depends on all others)

### 5. Quality Gates
Objective thresholds for pass/fail:
- Coverage >= 70%
- 0 CRITICAL security issues
- <= 3 HIGH security issues
- Code review >= 7/10
- Best practices <= 10 violations

### 6. Stub Phases
Phases 6-8 are stubs that:
- Generate placeholder reports
- Indicate "Not Yet Implemented"
- Activate automatically when code exists

## Why Not Use META-PROJECT Agents?

| Reason | Explanation |
|--------|-------------|
| Independence | SIOPV should be verifiable without META-PROJECT |
| Portability | Testing kit can be shared/exported with SIOPV |
| No pollution | No context mixing between framework and product |
| Clean separation | META-PROJECT = methodology, SIOPV = product |

## Agent Design Pattern

Each agent prompt follows this structure:

```markdown
TASK: What to do
SCOPE: Files to analyze
READ-ONLY: Do NOT modify any files

TOOLS TO USE:
- Allowed tools with examples
DO NOT USE: Restricted tools

EFFORT BUDGET: Max N tool calls

REPORT LENGTH: Flexible ~400 lines target
- Minimum: 50 lines
- Target: ~400 lines
- Maximum: 500 lines

REASONING: (for complex agents)
Step-by-step thinking process

CHECKS:
1. Specific check
2. Another check

OUTPUT FORMAT:
[Exact template to follow]

SAVE TO: [Full path with {TIMESTAMP}]
```

## Context7 Integration

The hallucination detector requires Context7 MCP for library verification.

**Fallback behavior:**
- If Context7 unavailable, skip API verification
- Note limitation in report
- Mark status as PARTIAL
- Continue with other checks

## Future Extensibility

### Adding New Phases
1. Create `prompts/phase-N-name.md` in comprehensive-test
2. Update SKILL.md workflow table
3. Stub automatically becomes active

### Adding New Foundation Checks
1. Create prompt in `prompts/`
2. Add to parallel invocation table
3. Update report numbering

### Custom Thresholds
Edit `reference/quality-gates.md` and update agent prompts accordingly.
