# META-COORDINATOR ORCHESTRATION STRATEGY
## OpenFGA Authentication Integration - Multi-Team Implementation

**Date:** 2026-02-12 10:17
**Project:** SIOPV
**Scope:** Complete OpenFGA Authentication Integration (21 tasks across 5 phases)
**Orchestrator:** Meta-Coordinator Agent
**Strategy:** Sequential multi-team deployment with cost-effective model selection

---

## EXECUTIVE SUMMARY

This document outlines the orchestration strategy for implementing the complete OpenFGA Authentication Integration plan using **5 sequential teams** (1 team per phase), with intelligent model selection to optimize cost while maintaining quality.

### Key Metrics
- **Total Tasks:** 21 (TASK-001 to TASK-021)
- **Total Phases:** 5
- **Files Modified:** 6
- **Files Created:** 4
- **Critical Gates:** 2 (TASK-010, TASK-021)
- **Expected PRs:** 4

---

## MULTI-TEAM STRATEGY

### Team Architecture

Each phase will be handled by a **dedicated team** that is created, executes its tasks, and is then shut down before the next phase begins. This ensures:

1. **Context isolation** - Each team focuses only on its phase requirements
2. **Cost efficiency** - Teams are active only when needed
3. **Clear phase boundaries** - Gates prevent progression until verification passes
4. **Simplified coordination** - Sequential execution reduces inter-team dependencies

### Phase-to-Team Mapping

| Phase | Team Name | Tasks | Focus Area | Critical Path |
|-------|-----------|-------|------------|---------------|
| **Phase 1** | `openfga-phase-1` | TASK-001 to TASK-003 | Config Foundation | ✅ Yes |
| **Phase 2** | `openfga-phase-2` | TASK-004 to TASK-010 | Adapter Auth + Gate | ✅ Yes |
| **Phase 3** | `openfga-phase-3` | TASK-011 to TASK-014 | Infrastructure Setup | ✅ Yes |
| **Phase 4** | `openfga-phase-4` | TASK-015 to TASK-017 | OIDC Migration | No |
| **Phase 5** | `openfga-phase-5` | TASK-018 to TASK-021 | Production Hardening + Final Gate | ✅ Yes |

---

## COST-EFFECTIVE MODEL SELECTION

### Model Selection Criteria

**Haiku (Fast & Cheap)** - Use for:
- Adding fields to classes (TASK-001)
- Updating test fixtures (TASK-008)
- Simple test creation following templates (TASK-003)
- File creation from templates (TASK-011, TASK-012)
- Adding comments/config blocks (TASK-016, TASK-020)

**Sonnet (Balanced)** - Use for:
- Complex logic changes (TASK-006: initialize() replacement)
- Test class creation requiring understanding (TASK-009)
- Script creation requiring error handling (TASK-013)
- Validation logic (TASK-018)
- Team coordination and planning

**Opus (Avoid unless necessary)** - Reserve for:
- Severe ambiguity requiring deep reasoning
- Complex architectural decisions
- Unplanned escalations

### Task-to-Model Mapping

| Task ID | Model | Rationale |
|---------|-------|-----------|
| TASK-001 | Haiku | Simple field addition (7 lines) |
| TASK-002 | N/A | Skip (already done) |
| TASK-003 | Haiku | Template-based test creation |
| TASK-004 | Haiku | Store settings in __init__ (7 lines + logging) |
| TASK-005 | Haiku | Add import statement (1 line) |
| TASK-006 | Sonnet | Complex config block replacement |
| TASK-007 | Haiku | Update logging (2 params) |
| TASK-008 | Haiku | Update fixtures (copy-paste pattern) |
| TASK-009 | Sonnet | New test class (8 tests, complex mocking) |
| TASK-010 | Sonnet | Gate verification (pytest + mypy + ruff) |
| TASK-011 | Haiku | Docker Compose from template |
| TASK-012 | Haiku | Authorization model (template) |
| TASK-013 | Sonnet | Bash script with error handling |
| TASK-014 | Sonnet | Integration tests (complex setup) |
| TASK-015 | Haiku | Add Keycloak service (simple YAML) |
| TASK-016 | Haiku | Add comments (no logic) |
| TASK-017 | Sonnet | Token refresh validation test |
| TASK-018 | Sonnet | Pydantic validator logic |
| TASK-019 | Sonnet | Validator tests (warnings.warn mocking) |
| TASK-020 | Haiku | Add comments (no logic) |
| TASK-021 | Sonnet | Final gate verification |

**Cost Optimization:** ~60% Haiku, ~40% Sonnet, 0% Opus (estimated 40-50% cost reduction vs all-Sonnet)

---

## PHASE BREAKDOWN

### Phase 1: Configuration Foundation (PR 1)
**Team:** `openfga-phase-1`
**Duration:** Short (3 tasks)
**Risk:** Low

**Tasks:**
- TASK-001: Add 7 settings fields to Settings class (Haiku)
- TASK-002: Verify .env.example (SKIP - already done)
- TASK-003: Add 3 settings tests (Haiku)

**Exit Criteria:**
- All tests pass: `pytest tests/unit/infrastructure/test_settings.py -v`
- No type errors in settings.py

**Team Composition:**
- 1 Team Lead (Sonnet) - coordination
- 1 Code Executor (Haiku) - implements TASK-001, TASK-003

---

### Phase 2: Adapter Authentication Support (PR 1 - continued)
**Team:** `openfga-phase-2`
**Duration:** Medium (6 tasks + gate)
**Risk:** Medium (critical path)

**Tasks:**
- TASK-004: Store auth settings in adapter __init__ (Haiku)
- TASK-005: Add credentials import (Haiku)
- TASK-006: Update initialize() with credential support (Sonnet)
- TASK-007: Update DI container logging (Haiku)
- TASK-008: Update ALL mock_settings fixtures (Haiku)
- TASK-009: Add adapter authentication unit tests (Sonnet)
- TASK-010: Run full unit test suite - GATE (Sonnet)

**Exit Criteria (GATE):**
- All unit tests pass: `pytest tests/unit/ -v --tb=short`
- No mypy errors in settings.py, openfga_adapter.py
- No ruff errors in modified files
- Zero regressions from existing 87+ tests

**Team Composition:**
- 1 Team Lead (Sonnet) - coordination + TASK-006, TASK-009, TASK-010
- 2 Code Executors (Haiku) - TASK-004, TASK-005, TASK-007, TASK-008

**Dependencies:**
- Requires Phase 1 completion (TASK-001 must be done)

---

### Phase 3: Infrastructure Setup (PR 2)
**Team:** `openfga-phase-3`
**Duration:** Medium (4 tasks)
**Risk:** Medium (Docker + script execution)

**Tasks:**
- TASK-011: Create docker-compose.yml (Haiku)
- TASK-012: Create authorization model file (Haiku)
- TASK-013: Create bootstrap script (Sonnet)
- TASK-014: Create real-server integration tests (Sonnet)

**Exit Criteria:**
- `docker compose config --quiet` passes
- `bash -n scripts/setup-openfga.sh` passes
- Integration tests skip gracefully when no server available

**Team Composition:**
- 1 Team Lead (Sonnet) - coordination + TASK-013, TASK-014
- 1 Code Executor (Haiku) - TASK-011, TASK-012

**Dependencies:**
- Requires Phase 2 gate pass (TASK-010)
- TASK-013 depends on TASK-011, TASK-012

---

### Phase 4: OIDC Migration (PR 3)
**Team:** `openfga-phase-4`
**Duration:** Short (3 tasks)
**Risk:** Low (mostly config)

**Tasks:**
- TASK-015: Add Keycloak to Docker Compose (Haiku)
- TASK-016: Add OIDC config comments (Haiku)
- TASK-017: Add token refresh validation test (Sonnet)

**Exit Criteria:**
- `docker compose config --quiet` passes
- Token refresh test passes

**Team Composition:**
- 1 Team Lead (Sonnet) - coordination + TASK-017
- 1 Code Executor (Haiku) - TASK-015, TASK-016

**Dependencies:**
- Requires Phase 3 completion (TASK-011)

---

### Phase 5: Production Hardening (PR 4)
**Team:** `openfga-phase-5`
**Duration:** Medium (4 tasks + final gate)
**Risk:** Medium (validation logic + final gate)

**Tasks:**
- TASK-018: Add Pydantic model_validator (Sonnet)
- TASK-019: Add validation tests (Sonnet)
- TASK-020: Add TLS/production comments (Haiku)
- TASK-021: Final full validation gate (Sonnet)

**Exit Criteria (FINAL GATE):**
- All unit tests pass: `pytest tests/unit/ -v --tb=short`
- No mypy errors in all modified files
- No ruff errors in all modified files
- Integration tests pass (if server available)

**Team Composition:**
- 1 Team Lead (Sonnet) - coordination + TASK-018, TASK-019, TASK-021
- 1 Code Executor (Haiku) - TASK-020

**Dependencies:**
- Requires Phase 2 gate pass (TASK-010)
- Requires TASK-001 (validator references fields)

---

## DEPENDENCY GRAPH (CRITICAL PATH HIGHLIGHTED)

```
[CRITICAL] TASK-001 (Settings) ──┬──> TASK-003 (Tests) ────────┐
                                 ├──> [CRITICAL] TASK-004 ──┐   │
                                 ├──> TASK-007 (Logging)    │   │
                                 └──> TASK-018 (Validator)  │   │
                                                            v   │
                         TASK-005 ──> [CRITICAL] TASK-006 ──┤   │
                                                            │   │
                         TASK-008 (Fixtures) ──> TASK-009 ──┤   │
                                                            │   │
                                    [GATE] TASK-010 <───────┴───┘
                                        │
                         [CRITICAL] TASK-011 ──┬──> TASK-012 ──> [CRITICAL] TASK-013
                                               └──> TASK-015 ──> TASK-016
                         TASK-013 + TASK-006 ──> TASK-014
                         TASK-009 ──> TASK-017
                         TASK-018 ──> TASK-019
                         TASK-011 ──> TASK-020
                         TASK-010 + TASK-017 + TASK-019 ──> [FINAL GATE] TASK-021
```

**Critical Path:** TASK-001 → TASK-004 → TASK-006 → TASK-010 → TASK-011 → TASK-013 → TASK-021

---

## GATE VERIFICATION STRATEGY

### Gate 1: TASK-010 (Phase 2 Exit)

**Verification Commands:**
```bash
cd ~/siopv
pytest tests/unit/ -v --tb=short
mypy src/siopv/infrastructure/config/settings.py src/siopv/adapters/authorization/openfga_adapter.py --ignore-missing-imports
ruff check src/siopv/infrastructure/config/settings.py src/siopv/adapters/authorization/openfga_adapter.py
```

**Pass Criteria:**
- Zero test failures
- Zero mypy errors
- Zero ruff errors
- No regressions in existing tests

**Failure Protocol:**
1. Stop all phase progression
2. Report failure details to meta-coordinator
3. Meta-coordinator analyzes root cause
4. Fix issued or escalated to user
5. Re-run gate verification

---

### Gate 2: TASK-021 (Phase 5 Exit - Final)

**Verification Commands:**
```bash
cd ~/siopv
pytest tests/unit/ -v --tb=short
mypy src/siopv/infrastructure/config/settings.py src/siopv/adapters/authorization/openfga_adapter.py src/siopv/infrastructure/di/authorization.py --ignore-missing-imports
ruff check src/siopv/infrastructure/config/settings.py src/siopv/adapters/authorization/openfga_adapter.py src/siopv/infrastructure/di/authorization.py
```

**Pass Criteria:**
- All unit tests pass (including new validation tests)
- Zero mypy errors across all modified files
- Zero ruff errors across all modified files
- Integration tests skip gracefully or pass (if server available)

**Failure Protocol:**
- Same as Gate 1

---

## REPORTING STRUCTURE

### Directory Structure
```
~/siopv/.claude/docs/2026-02-12-1017-openfga-authentication-multi-team-orchestrated-implementation-execution-plan-phases-1-to-5-complete/
├── 2026-02-12-1017-meta-coordinator-multi-team-orchestration-strategy-cost-effective-model-selection-five-sequential-phases-openfga-authentication-integration.md (THIS FILE)
├── 2026-02-12-1017-phase-1-configuration-foundation-execution-report-task-001-to-003-settings-fields-tests-completion-status.md
├── 2026-02-12-1017-phase-2-adapter-authentication-support-execution-report-task-004-to-010-gate-verification-results.md
├── 2026-02-12-1017-phase-3-infrastructure-setup-execution-report-task-011-to-014-docker-compose-bootstrap-integration-tests.md
├── 2026-02-12-1017-phase-4-oidc-migration-execution-report-task-015-to-017-keycloak-token-refresh-validation.md
├── 2026-02-12-1017-phase-5-production-hardening-execution-report-task-018-to-021-final-gate-validation-completion.md
└── 2026-02-12-1017-final-summary-openfga-authentication-integration-complete-all-phases-files-modified-verification-results-next-steps.md
```

### Report Requirements

Each phase report must include:
1. **Executive Summary** - Phase goal, tasks completed, outcome
2. **Task Execution Details** - Per-task status, model used, issues encountered
3. **File Changes** - All files modified/created with line counts
4. **Verification Results** - Test outputs, mypy/ruff results
5. **Issues and Resolutions** - Any problems and how they were solved
6. **Next Phase Handoff** - Dependencies satisfied for next phase

Final summary report must include:
1. **All phases overview** - Status of each phase
2. **Complete file manifest** - All files modified/created
3. **Verification summary** - Final gate results
4. **PR readiness** - Which tasks belong to which PR
5. **Next steps** - User actions required (if any)

---

## AMBIGUITY HANDLING PROTOCOL

### Decision Authority Matrix

| Scenario | Action |
|----------|--------|
| Template-based task has clear instructions | Proceed autonomously |
| Code snippet has minor syntax ambiguity | Use best judgment, document in report |
| Test expectations unclear | Ask meta-coordinator |
| Gate failure root cause unclear | Analyze, report to meta-coordinator |
| Missing dependency or tool | Escalate to user via meta-coordinator |
| Conflicting requirements | Escalate to user via meta-coordinator |

### Escalation Flow

```
Team Member → Team Lead → Meta-Coordinator → User (if needed)
```

**Example Escalations:**
- "TASK-006 requires understanding of SDK credential API - need Sonnet model"
- "TASK-010 gate failing due to unexpected mypy error in existing code - needs investigation"
- "Docker Compose healthcheck timing out - may need adjusted timeout values"

---

## EXECUTION TIMELINE (ESTIMATED)

| Phase | Duration Estimate | Cumulative |
|-------|-------------------|------------|
| Phase 1 | 5-10 min | 10 min |
| Phase 2 | 15-20 min | 30 min |
| Phase 3 | 10-15 min | 45 min |
| Phase 4 | 5-10 min | 55 min |
| Phase 5 | 10-15 min | 70 min |
| **Total** | **45-70 min** | **~1 hour** |

*Note: Estimates include team creation, task execution, verification, and reporting. Actual time may vary based on gate verification results.*

---

## RISK MITIGATION

### High-Risk Tasks

| Task | Risk | Mitigation |
|------|------|------------|
| TASK-006 | Complex SDK configuration replacement | Use Sonnet, verify against SDK docs |
| TASK-010 | Gate may reveal unexpected failures | Thorough unit test review before gate |
| TASK-013 | Bash script may have syntax errors | Use `bash -n` verification |
| TASK-021 | Final gate may reveal integration issues | Comprehensive pre-gate check |

### Rollback Plan

Each phase is designed to be independently reversible:

- **Phase 1-2:** `git revert <commit>` (all changes backward-compatible)
- **Phase 3:** Delete Docker Compose files, no code changes
- **Phase 4:** Configuration only, no breaking changes
- **Phase 5:** Validation logic is non-breaking (warnings only)

---

## SUCCESS CRITERIA

### Overall Success Defined As:

✅ All 21 tasks completed
✅ Both gates (TASK-010, TASK-021) pass
✅ Zero regressions in existing test suite
✅ All new tests pass
✅ Zero mypy/ruff errors in modified files
✅ Docker Compose validates successfully
✅ Bootstrap script executes without errors
✅ 4 PRs ready for review (task grouping documented)

---

## NEXT STEPS

1. ✅ Strategy report created (THIS FILE)
2. ⏳ Create Phase 1 team (`openfga-phase-1`)
3. ⏳ Execute Phase 1 tasks
4. ⏳ Verify Phase 1 completion
5. ⏳ Repeat for Phases 2-5
6. ⏳ Create final summary report
7. ⏳ Report completion to orchestrator

---

## META-COORDINATOR NOTES

**Orchestration Delegation:**
The main orchestrator has delegated 100% of the implementation to this meta-coordinator. All decisions within the defined strategy are autonomous. Escalations to the user should only occur for:
- Unexpected blockers not covered in the plan
- Ambiguities requiring user preference decisions
- Gate failures that cannot be resolved programmatically

**Communication Protocol:**
- Regular progress updates to team lead (orchestrator) via SendMessage
- Phase completion reports after each phase
- Gate results reported immediately
- Final summary upon completion

**Cost Tracking:**
Estimated model usage:
- Haiku: ~12 tasks (60% of work)
- Sonnet: ~9 tasks (40% of work)
- Opus: 0 tasks (0% of work)

Expected cost reduction: ~40-50% vs all-Sonnet approach

---

**Report Generated:** 2026-02-12 10:17
**Meta-Coordinator:** Ready to begin Phase 1
**Status:** Strategy approved, awaiting execution start
