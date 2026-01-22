# Risk Scoring Inconsistencies - Fixed Issues

## Overview
This document summarizes the critical fixes implemented to resolve risk scoring inconsistencies across the PhishGuard backend and frontend components.

## Issues Identified and Fixed

### 1. Layer Name Mismatches ✅ FIXED
**Problem**: Backend and frontend used inconsistent layer names
- **Backend**: Layer 1 returned `"Layer 1"`, Layer 2 returned `"Layer 2 (Advanced)"`, Layer 3 returned `"Layer 3 (Threat)"`
- **Frontend**: Expected `"Layer 1 (Basic)"`, `"Layer 2 (Advanced)"`, `"Layer 3 (Threat)"`

**Fix**: Updated `layer1.py` to return `"Layer 1 (Basic)"` instead of `"Layer 1"`

**Files Modified**:
- `backend/app/logic/layer1.py` (line 706)

### 2. Risk Score Calculation Misalignment ✅ FIXED
**Problem**: Frontend displayed raw layer scores without applying backend's weighted calculation logic

**Fix**: 
- Backend RiskScorer now includes `max_score` calculation in response
- Frontend uses backend's weighted layer scores from `risk_analysis.breakdown.layer_scores`
- Added missing `lexical` check weight (1.0) in RiskScorer

**Files Modified**:
- `backend/app/models/risk_scorer.py` (lines 30, 115)
- `frontend/src/components/RiskSummaryCard.jsx` (lines 13-16)

### 3. Risk Threshold Inconsistencies ✅ FIXED
**Problem**: Different risk level thresholds between backend and frontend
- **Backend**: Used thresholds (0.5, 2.0, 4.0, 6.0)
- **Frontend**: Used thresholds (2.0, 6.0, 12.0, 18.40)

**Fix**: Aligned both to use consistent thresholds (0.0, 2.0, 6.0, 12.0+)

**Files Modified**:
- `backend/app/models/risk_scorer.py` (lines 49-55)
- `frontend/src/components/RiskSummaryCard.jsx` (lines 21-38)

### 4. Max Score Constants ✅ FIXED
**Problem**: Frontend hardcoded max score of 18.40, backend had no explicit max score

**Fix**: 
- Backend calculates dynamic max_score based on check weights and layer weights
- Frontend uses backend's `max_score` from API response with fallback

**Max Score Calculation**:
```
Layer 1 (Basic) - weight 1.0: (0.3 + 0.8 + 1.0 + 1.0) * 1.0 = 3.1
Layer 2 (Advanced) - weight 1.5: (2.0 + 1.2 + 1.2 + 1.8) * 1.5 = 9.3  
Layer 3 (Threat) - weight 2.0: (1.5 + 1.0 + 1.3) * 2.0 = 7.6
Total Max Score: 3.1 + 9.3 + 7.6 = 20.0
```

**Files Modified**:
- `backend/app/models/risk_scorer.py` (lines 39-47, 115)
- `frontend/src/components/RiskSummaryCard.jsx` (line 19)
- `frontend/src/components/DiagnosticDetailsCard.jsx` (line 65, 98)

### 5. Diagnostic Details Score Summation ✅ FIXED
**Problem**: Diagnostic details didn't correctly sum to total risk score

**Fix**: Updated DiagnosticDetailsCard to use backend's max_score for consistent display

**Files Modified**:
- `frontend/src/components/DiagnosticDetailsCard.jsx` (lines 65, 98)

## Risk Level Classification (Now Synchronized)

| Score Range | Risk Level | Color |
|-------------|------------|-------|
| 0.00 - 0.00 | Benign | #22C55E |
| 0.01 - 2.00 | Low | #3B82F6 |
| 2.01 - 6.00 | Medium | #F59E0B |
| 6.01 - 12.00 | High | #EF4444 |
| 12.01+ | Critical | #991B1B |

## Check Weights (Now Complete)

| Check | Weight | Layer |
|-------|--------|-------|
| length | 0.3 | Layer 1 |
| schema | 0.8 | Layer 1 |
| tld | 1.0 | Layer 1 |
| lexical | 1.0 | Layer 1 |
| homograph | 2.0 | Layer 2 |
| depth | 1.2 | Layer 2 |
| keyword | 1.2 | Layer 2 |
| punycode | 1.8 | Layer 2 |
| chained | 1.5 | Layer 3 |
| dynamic | 1.0 | Layer 3 |
| redirect | 1.3 | Layer 3 |

## Layer Weights

| Layer | Weight |
|-------|--------|
| Layer 1 (Basic) | 1.0 |
| Layer 2 (Advanced) | 1.5 |
| Layer 3 (Threat) | 2.0 |

## Verification

The fixes ensure:
1. **Deterministic scoring**: Same URL always produces same score
2. **Consistent display**: Frontend accurately reflects backend calculations
3. **Transparent traceability**: Diagnostic details correctly sum to total
4. **Synchronized thresholds**: Risk levels match across components
5. **Dynamic max score**: Automatically adjusts to weight changes

## Testing

Use the provided `test_scoring.py` script to verify scoring consistency:
```bash
python test_scoring.py
```

This will test various URL patterns and confirm that:
- Layer names are consistent
- Scores calculate correctly
- Risk thresholds align
- Max scores synchronize
- Frontend compatibility is maintained
