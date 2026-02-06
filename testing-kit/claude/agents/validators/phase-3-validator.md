# Phase 3 Validator - ML Classification

## Purpose

Validate Phase 3 (ML Classification with XAI) implementation.

## Scope

- **READ-ONLY** analysis (no modifications)

## Files to Analyze

```
src/siopv/adapters/ml/xgboost_classifier.py
src/siopv/adapters/ml/feature_engineer.py
src/siopv/adapters/ml/shap_explainer.py
src/siopv/adapters/ml/lime_explainer.py
src/siopv/adapters/ml/model_persistence.py
src/siopv/adapters/persistence/cisa_kev_loader.py
src/siopv/infrastructure/ml/
```

## Checks

### 1. Dataset Construction
- [ ] CISA KEV loader with schema validation
- [ ] Path traversal protection
- [ ] Proper data loading and parsing

### 2. Feature Engineering
- [ ] 14 features defined (CVSS + EPSS + temporal + context)
- [ ] Feature normalization/scaling
- [ ] Feature documentation

### 3. XGBoost Classifier
- [ ] Optuna hyperparameter optimization
- [ ] Proper train/test split
- [ ] Cross-validation
- [ ] Model evaluation metrics

### 4. Class Imbalance
- [ ] SMOTE implementation
- [ ] Proper sampling strategy
- [ ] Imbalanced-learn integration

### 5. SHAP Explainer
- [ ] TreeExplainer usage
- [ ] Global feature importance
- [ ] SHAP value extraction
- [ ] Visualization support

### 6. LIME Explainer
- [ ] LimeTabularExplainer setup
- [ ] Per-prediction explanations
- [ ] Configurable random seeds
- [ ] Feature contribution output

### 7. Model Persistence
- [ ] SHA-256 integrity check
- [ ] HMAC authentication
- [ ] Path traversal protection
- [ ] Versioned model storage

## Report Output

Save to: `~/siopv/claude-verification-reports/{timestamp}/08-phase-3-ml.md`

## Report Format

```markdown
# Phase 3 - ML Classification Validation Report
**Date:** {timestamp}
**Status:** PASS/FAIL

## Summary
- Files analyzed: N
- Checks passed: N/N
- Issues found: N

## Dataset Construction
| Check | Status | Notes |
|-------|--------|-------|
| CISA KEV loader | PASS/FAIL | |
| Schema validation | PASS/FAIL | |
| Path protection | PASS/FAIL | |

## Feature Engineering
| Check | Status | Notes |
|-------|--------|-------|
| 14 features | PASS/FAIL | |
| Normalization | PASS/FAIL | |
| Documentation | PASS/FAIL | |

## XGBoost Classifier
| Check | Status | Notes |
|-------|--------|-------|
| Optuna optimization | PASS/FAIL | |
| Train/test split | PASS/FAIL | |
| Cross-validation | PASS/FAIL | |
| Metrics | PASS/FAIL | |

## SMOTE
| Check | Status | Notes |
|-------|--------|-------|
| Implementation | PASS/FAIL | |
| Sampling strategy | PASS/FAIL | |

## SHAP Explainer
| Check | Status | Notes |
|-------|--------|-------|
| TreeExplainer | PASS/FAIL | |
| Feature importance | PASS/FAIL | |
| Value extraction | PASS/FAIL | |

## LIME Explainer
| Check | Status | Notes |
|-------|--------|-------|
| LimeTabularExplainer | PASS/FAIL | |
| Per-prediction | PASS/FAIL | |
| Random seeds | PASS/FAIL | |

## Model Persistence
| Check | Status | Notes |
|-------|--------|-------|
| SHA-256 integrity | PASS/FAIL | |
| HMAC auth | PASS/FAIL | |
| Path protection | PASS/FAIL | |

## Issues
[List any issues found]

## Quality Gate
- Threshold: All critical checks pass
- Result: PASS/FAIL
```

## Quality Gate

- **PASS**: All checks pass
- **FAIL**: Any critical check fails
