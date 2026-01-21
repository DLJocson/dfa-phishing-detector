# Layer 3 DFA Extensions - Implementation Documentation

## Overview

This document describes the 5 new DFA detectors added to Layer 3 (Threat Detection) of the phishing detector system. All implementations are **pure DFAs** with no regex, string buffering, counters, or auxiliary variables.

---

## 1. EncodedProtocolDFA

### Purpose
Detects percent-encoded embedded protocols in query parameters (e.g., `%68%74%74%70` = "http", `%3A%2F%2F` = "://")

### Risk Score
**2.5** (High risk - indicates URL injection attempts)

### DFA Architecture

**States:**
- `START`: Initial state, scanning for `%`
- `P`: After seeing `%`
- `H6`, `H68`, `H68P`, `T7`, `T74`, `T74P`, `T27`, `T274`, `T274P`, `P7`, `P70`: sequence for `%68%74%74%70` (http)
- `HTTPP`, `C3`, `C3A`, `C3AP`, `S2`, `S2F`, `S2FP`, `S22`, `S22F`: sequence for `%3A%2F%2F` (://)
- `FOUND`: Accepting state when full encoded protocol detected

**Transition Logic:**
1. On `%` go to `P`
2. Parse hex digits character-by-character for `http`
3. After `http`, parse encoded `://`
4. Accept when `S22F` reached (`FOUND`)

**Detection Examples:**
- ✅ `callback=%68%74%74%70%3A%2F%2Fevil.com` → TRIGGERED
- ✅ `next=page&data=%3A%2F%2F` → TRIGGERED
- ❌ `url=normal_value` → NOT TRIGGERED

---

## 2. FragmentRedirectDFA

### Purpose
Detects fragment-based redirects using `#` (e.g., `#//evil.com`, `#/http://...`)

### Risk Score
**1.5** (Medium-high risk - client-side redirect vulnerability)

### DFA Architecture

**States:** `START`, `FOUND_HASH`, `FOUND_SLASH`, `FOUND_DOUBLE_SLASH`, `FOUND_H`, `FOUND_T`, `FOUND_T2`, `FOUND_P`, `FOUND_HTTP`

**Transition Logic:**
1. Detect `#`
2. If followed by `/`, accept on second `/`
3. If followed by `http`, accept on `http:`

**Detection Examples:**
- ✅ `#//evil.com` → TRIGGERED
- ✅ `#/http://malicious.site` → TRIGGERED
- ❌ `#section` → NOT TRIGGERED

---

## 3. ShortenerDFA

### Purpose
Detects known URL shortener domains that may obfuscate destination

### Risk Score
**2.0** (Medium-high risk - link obfuscation)

### DFA Architecture

**Trie-based DFA** matching exact domains:
- `bit.ly`, `tinyurl.com`, `t.co`, `is.gd`

**Detection Examples:**
- ✅ `bit.ly` → TRIGGERED
- ❌ `bit.ly.phishing.com` → NOT TRIGGERED (not exact match)

---

## 4. CredentialPathDFA

### Purpose
Detects credential-harvesting paths in URLs

### Risk Score
**1.2** (Medium risk - phishing attempt indicator)

### DFA Architecture

**Trie-based DFA** matching keywords: `login`, `verify`, `update`, `auth`, `session`
Resets on `/` to allow matching per path segment.

**Detection Examples:**
- ✅ `/login` → TRIGGERED
- ✅ `/user/update` → TRIGGERED
- ❌ `/about` → NOT TRIGGERED

---

## 5. SuspiciousTLDDFA

### Purpose
Detects risky top-level domains commonly associated with malicious sites

### Risk Score
**1.0** (Medium risk)

**Trie-based DFA** matching TLDs (case-insensitive): `.xyz`, `.tk`, `.top`, `.ru`, `.cn`

**Detection Examples:**
- ✅ `malicious.xyz` → TRIGGERED
- ❌ `google.com` → NOT TRIGGERED

---

## Integration with Layer3

`Layer3` now manages 8 DFA detectors: chained, dynamic, redirect, encoded_protocol, fragment_redirect, shortener, credential_path, suspicious_tld.

**Risk score aggregation:** weighted sum of all detector scores (max 14.5).

**Output includes:** which detectors triggered, risk scores, reasons, details, and final `layer_risk_score`.

---

## Testing

Run:

```bash
cd c:\Users\krisq\Desktop\AUTOMATA\dfa-phishing-detector
python test_layer3_extensions.py
```

Covers individual DFA tests and integration tests.

---

## Example high-risk URL

`http://bit.ly/login?redirect=%68%74%74%70%3A%2F%2Fevil.xyz#//malware.com`

Triggers: Shortener (2.0) + CredentialPath (1.2) + EncodedProtocol (2.5) + SuspiciousTLD (1.0) + FragmentRedirect (1.5) → Total 8.2 (high risk).
