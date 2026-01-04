# Layer 1 DFA Implementation - Formal Specification

## Overview

Layer 1 implements three independent Deterministic Finite Automata (DFAs) using **state-transition tables** and **single while loops** for character processing, following formal automata theory.

---

## Mathematical Foundation

### DFA Definition
A DFA is formally defined as a 5-tuple: **M = (Q, Σ, δ, q₀, F)**

Where:
- **Q**: Set of states
- **Σ**: Alphabet (input symbols)
- **δ: Q × Σ → Q**: Transition function
- **q₀ ∈ Q**: Initial state
- **F ⊆ Q**: Set of accepting/final states

### Transition Function
The transition function maps a (state, character) pair to the next state:

$$\delta(q, \sigma) \rightarrow q'$$

In our implementation, represented as a **state-transition table** (dictionary):

```python
transition_table = {
    (current_state, char_type): next_state,
    ...
}
```

---

## DFA 1: Length DFA

### Specification

**Purpose**: Detect elongated URLs used for obfuscation

**Mathematical Definition**:
- **Q** = {START, CHECKING, ACCEPT, REJECT}
- **Σ** = {any character in URL}
- **q₀** = START
- **F** = {ACCEPT, REJECT}
- **Threshold**: 75 characters (configurable)

### State Diagram

```
START → CHECKING → CHECKING → ... → ACCEPT (if length > 75)
                                  ↓
                                REJECT (if length ≤ 75)
```

### Transition Logic

| Current State | Input (char_count) | Next State | Condition |
|---|---|---|---|
| START | any | CHECKING | Begin processing |
| CHECKING | count ≤ 75 | CHECKING | Continue counting |
| CHECKING | count > 75 | ACCEPT | Suspicious length |
| ACCEPT, REJECT | any | same | Terminal states |

### Risk Score
- **ACCEPT**: 0.3 (low weight - basic check)
- **REJECT**: 0.0 (no risk)

### Implementation Details

```python
def _transition(self, state: str, char_count: int) -> str:
    if state == self.START:
        return self.CHECKING
    elif state == self.CHECKING:
        if char_count > self.threshold:
            return self.ACCEPT
        else:
            return self.CHECKING
    else:
        return state
```

**Single While Loop Processing**:
```python
i = 0
while i < len(url):
    char_count = i + 1
    state = self._transition(state, char_count)
    i += 1
```

---

## DFA 2: Schema DFA

### Specification

**Purpose**: Identify suspicious protocols (file://, data:, javascript:, etc.)

**Mathematical Definition**:
- **Q** = {START, READING_SCHEMA, COLON, SLASH1, SLASH2, VALIDATE, ACCEPT, REJECT}
- **Σ** = {alpha, ':', '/', default}
- **q₀** = START
- **F** = {ACCEPT, REJECT}

### State Diagram

```
START → READING_SCHEMA → COLON → SLASH1 → SLASH2 → VALIDATE → ACCEPT/REJECT
                ↓                                              ↓
                └──────────────── REJECT (invalid format) ────┘
```

### Transition Table

| (State, Char Type) | Next State | Notes |
|---|---|---|
| (START, alpha) | READING_SCHEMA | Begin schema |
| (READING_SCHEMA, alpha) | READING_SCHEMA | Continue reading |
| (READING_SCHEMA, ':') | COLON | Schema ends |
| (COLON, '/') | SLASH1 | Found first slash |
| (SLASH1, '/') | SLASH2 | Found second slash |
| (SLASH2, any) | VALIDATE | Schema complete |
| (VALIDATE, any) | VALIDATE | Terminal state |

### Risk Score

**Suspicious Schemas** (risk_score = 0.8):
- `file` - Local file access
- `data` - Data URI with embedded content
- `javascript` - Code execution
- `vbscript` - Legacy code execution
- `ftp`, `telnet`, `gopher` - Legacy protocols

**Safe Schemas** (risk_score = 0.0):
- `http`
- `https`

### Implementation

**Character Classification**:
```python
def _get_char_type(self, char: str) -> str:
    if char.isalpha(): return 'alpha'
    elif char == ':': return ':'
    elif char == '/': return '/'
    else: return 'default'
```

**Single While Loop Processing**:
```python
i = 0
while i < len(input_string):
    char = input_string[i]
    state, schema = self._transition(state, char, schema)
    i += 1
    if state in {self.ACCEPT, self.REJECT, self.VALIDATE}:
        break
```

---

## DFA 3: TLD DFA

### Specification

**Purpose**: Flag high-risk top-level domains

**Mathematical Definition**:
- **Q** = {START, COLLECTING_TLD, LOOKUP, ACCEPT, REJECT}
- **Σ** = {alpha, digit, hyphen, end, default}
- **q₀** = START
- **F** = {ACCEPT, REJECT}

### State Diagram

```
START → COLLECTING_TLD → LOOKUP → ACCEPT (if in high-risk list)
          ↓                     ↓
          └─────→ REJECT (if not in high-risk list)
```

### Transition Table

| (State, Char Type) | Next State | Notes |
|---|---|---|
| (START, alpha) | COLLECTING_TLD | Begin TLD |
| (START, '.') | COLLECTING_TLD | Strip leading dot |
| (COLLECTING_TLD, alpha) | COLLECTING_TLD | Continue |
| (COLLECTING_TLD, digit) | COLLECTING_TLD | Continue |
| (COLLECTING_TLD, hyphen) | COLLECTING_TLD | Continue |
| (COLLECTING_TLD, end) | LOOKUP | Transition to lookup |
| (LOOKUP, any) | LOOKUP | Terminal state |

### Risk Score
- **ACCEPT**: 1.0 (highest weight in Layer 1 - strongest indicator)
- **REJECT**: 0.0 (no risk)

### High-Risk TLD Categories

**Executable Extensions**:
- `.zip`, `.mov`, `.exe`, `.bat`, `.scr`, `.app`, `.run`

**Trust-Building Generic TLDs**:
- `.link`, `.click`, `.download`, `.online`, `.site`, `.website`

**Free/Cheap Registration (High Abuse)**:
- `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.pw`

**Suspicious Intent**:
- `.xyz`, `.top`, `.review`, `.accountant`, `.bid`, `.date`, `.faith`, `.loan`
- `.men`, `.party`, `.racing`, `.science`, `.stream`, `.trade`, `.win`, `.work`, `.ooo`

### Implementation

**Character Classification**:
```python
def _get_char_type(self, char: str, is_last: bool = False) -> str:
    if char.isalpha(): return 'alpha'
    elif char.isdigit(): return 'digit'
    elif char == '-': return 'hyphen'
    elif is_last: return 'end'
    else: return 'default'
```

**Single While Loop Processing**:
```python
i = 0
while i < len(tld_lower):
    char = tld_lower[i]
    is_last = (i == len(tld_lower) - 1)
    state = self._transition(state, char, is_last)
    i += 1

# Final database lookup
if tld_lower in self.high_risk_tlds:
    final_state = self.ACCEPT
else:
    final_state = self.REJECT
```

---

## Layer 1 Coordinator

### Purpose
Aggregates results from three independent DFAs and calculates combined risk.

### Process Flow

```
URL Input
    ↓
Tokenizer (extract components)
    ↓
┌─────────────────────────────────────────┐
│  Length DFA  →  [triggered, risk_score] │
│  Schema DFA  →  [triggered, risk_score] │
│  TLD DFA     →  [triggered, risk_score] │
└─────────────────────────────────────────┘
    ↓
Aggregate Results:
  - triggered_count (how many checks fired)
  - total_checks = 3
  - layer_risk_score (sum of individual risk scores)
    ↓
Return Comprehensive Assessment
```

### Risk Calculation

```python
layer_risk_score = sum([
    length_result.risk_score,      # 0.0 or 0.3
    schema_result.risk_score,      # 0.0 or 0.8
    tld_result.risk_score          # 0.0 or 1.0
])
```

**Example Calculation**:
- URL: `https://google.com.secure-login.tk`
- Length: 37 chars → REJECT, risk = 0.0
- Schema: `https` → REJECT, risk = 0.0
- TLD: `.tk` → ACCEPT, risk = 1.0
- **Layer 1 Risk Score = 1.0** (flagged as suspicious due to high-risk TLD)

---

## Key Features

### 1. **No Threading or Multiprocessing**
- All DFAs run synchronously in single thread
- Single while loop for character processing
- Deterministic execution without race conditions

### 2. **State-Transition Table Design**
- Explicit state representation
- Clear transition logic
- Easy to visualize and debug
- Mathematically formal

### 3. **Transparent Reporting**
- Each DFA reports its state transitions
- Reasons for acceptance/rejection documented
- Risk scores break down by check

### 4. **Composability**
- DFAs operate independently
- Results cleanly aggregated
- Easy to add new checks or modify thresholds

---

## Usage Example

```python
from app.logic.layer1 import Layer1

layer1 = Layer1()

# Analyze URL
result = layer1.analyze("https://www.paypal.com.secure-login.tk")

print(f"Layer: {result['layer']}")
print(f"Triggered Checks: {result['triggered_count']}/{result['total_checks']}")
print(f"Layer Risk Score: {result['layer_risk_score']}")

# Access individual DFA results
print("\nLength Check:")
print(f"  State: {result['checks']['length']['state']}")
print(f"  Risk Score: {result['checks']['length']['risk_score']}")

print("\nSchema Check:")
print(f"  State: {result['checks']['schema']['state']}")
print(f"  Risk Score: {result['checks']['schema']['risk_score']}")

print("\nTLD Check:")
print(f"  State: {result['checks']['tld']['state']}")
print(f"  Reason: {result['checks']['tld']['reason']}")
print(f"  Risk Score: {result['checks']['tld']['risk_score']}")
```

**Output**:
```
Layer: Layer 1 (Basic)
Triggered Checks: 1/3
Layer Risk Score: 1.0

Length Check:
  State: REJECT
  Risk Score: 0.0

Schema Check:
  State: REJECT
  Risk Score: 0.0

TLD Check:
  State: ACCEPT
  Reason: High-risk TLD detected: .tk
  Risk Score: 1.0
```

---

## Performance Characteristics

| Operation | Complexity | Notes |
|---|---|---|
| Length DFA | O(n) | Linear scan of URL |
| Schema DFA | O(m) | m = schema length (typically 3-20 chars) |
| TLD DFA | O(k) | k = TLD length (typically 2-6 chars) |
| TLD Lookup | O(1) | Hash table lookup in high_risk_tlds set |
| **Total Layer 1** | **O(n)** | Dominated by length check |

---

## Integration with Risk Scorer

Layer 1 risk scores are passed to the Risk Scorer module:

```python
# In Risk Scorer
layer_weight = 1.0  # Layer 1 base weight
check_weight = risk_score  # Varies by check (0.3, 0.8, 1.0)

final_score = layer_weight × check_weight
```

Example:
- TLD check triggers: `1.0 × 1.0 = 1.0`
- Length check triggers: `1.0 × 0.3 = 0.3`
- Combined with Layers 2 and 3 for final risk classification

---

## Conclusion

This formal DFA implementation provides:
✓ Mathematically sound automata theory application
✓ Clear state transitions and deterministic behavior
✓ Single-threaded, efficient processing
✓ Transparent risk assessment
✓ Foundation for Layers 2 and 3 DFAs
