"""
===========================================
LAYER 1 - BASIC DFA
===========================================
Formal DFA implementation for basic URL security checks.

States:
  - START: Initial state before processing
  - CHECKING: Actively scanning characters
  - ACCEPT: Suspicious condition detected (risk flag triggered)
  - REJECT: Safe condition confirmed (no risk)

Transition Function δ(q, σ) → q':
  Maps (current_state, input_character) to next_state

Risk Scoring:
  - Each check has a weight (0.3-1.0 for Layer 1 basic checks)
  - ACCEPT states trigger risk accumulation
  - Final score determines if check contributes to overall risk

Three DFAs in Layer 1:
1. Length DFA: Detects elongated URLs (obfuscation technique)
2. Schema DFA: Identifies suspicious protocols
3. TLD DFA: Flags high-risk top-level domains
"""

from typing import Dict, Tuple
from .tokenizer import TokenizerDFA


# ========================================
# LENGTH DFA - State Transition Table
# ========================================

class LengthDFA:
    """
    Formal DFA for URL length anomaly detection.
    
    Mathematical Definition:
    - Q = {START, CHECKING, ACCEPT, REJECT}
    - Σ = {any character in URL}
    - δ: Q × Σ → Q (transition function)
    - q0 = START (initial state)
    - F = {ACCEPT, REJECT} (final states)
    - Threshold: 75 characters
    
    Behavior:
    - START: Initialize character counter
    - CHECKING: Count each character; if count > threshold → ACCEPT
    - ACCEPT: Suspicious length detected (risk score: 0.3)
    - REJECT: Normal length (no risk)
    """
    
    def __init__(self, threshold: int = 75):
        self.threshold = threshold
        self.risk_score = 0.3  # Weight for length check
        
        # Define States
        self.START = "START"
        self.CHECKING = "CHECKING"
        self.ACCEPT = "ACCEPT"
        self.REJECT = "REJECT"
        
        self.initial_state = self.START
        self.accepting_states = {self.ACCEPT}
    
    def _transition(self, state: str, char_count: int) -> str:
        """
        Transition function δ(q, σ) → q'
        
        For length DFA:
        - σ is represented by the character count
        - Input: current state, accumulated character count
        - Output: next state
        """
        if state == self.START:
            # START: Move to CHECKING (begin processing)
            return self.CHECKING
        
        elif state == self.CHECKING:
            # CHECKING: Continue until threshold exceeded
            if char_count > self.threshold:
                return self.ACCEPT  # Too long → suspicious
            else:
                return self.CHECKING  # Keep counting
        
        else:
            # ACCEPT and REJECT are terminal states
            return state
    
    def check(self, url: str) -> Dict:
        """
        Run DFA simulation with single while loop.
        
        Process:
        1. Initialize state to START
        2. Count characters in single loop
        3. Apply transition function
        4. Check if final state is accepting
        5. Return risk score if accepting, 0 if rejecting
        """
        # Initialize DFA
        state = self.initial_state
        length = len(url)
        
        # State Transition Loop: Single while loop processing input
        i = 0
        while i < len(url):
            # Transition based on accumulated length
            char_count = i + 1
            state = self._transition(state, char_count)
            i += 1
        
        # Final transition to determine acceptance
        state = self._transition(state, length)
        
        # Check if final state is accepting
        triggered = state in self.accepting_states
        
        return {
            "triggered": triggered,
            "state": state,
            "reason": f"URL length ({length}) exceeds threshold ({self.threshold})" if triggered else f"URL length ({length}) is acceptable",
            "value": length,
            "threshold": self.threshold,
            "risk_score": self.risk_score if triggered else 0.0
        }


# ========================================
# SCHEMA DFA - State Transition Table
# ========================================

class SchemaDFA:
    """
    Formal DFA for protocol/schema validation.
    
    Mathematical Definition:
    - Q = {START, READING_SCHEMA, COLON, SLASH1, SLASH2, VALIDATE, ACCEPT, REJECT}
    - Σ = {alphanumeric characters, ':', '/', and others}
    - δ: Q × Σ → Q (transition function defined as lookup table)
    - q0 = START
    - F = {ACCEPT, REJECT}
    
    DFA Logic:
    START → READING_SCHEMA → COLON → SLASH1 → SLASH2 → VALIDATE
    
    Input example: "http://" or "file://"
    - Valid schemas: "http", "https" → ACCEPT (risk_score: 0.0)
    - Suspicious schemas: "file", "data", "javascript" → ACCEPT (risk_score: 0.8)
    - Unknown schemas: anything else → REJECT (risk_score: 0.0)
    """
    
    def __init__(self):
        self.risk_score = 0.8  # Weight for schema check
        
        # Define States
        self.START = "START"
        self.READING_SCHEMA = "READING_SCHEMA"
        self.COLON = "COLON"
        self.SLASH1 = "SLASH1"
        self.SLASH2 = "SLASH2"
        self.VALIDATE = "VALIDATE"
        self.ACCEPT = "ACCEPT"
        self.REJECT = "REJECT"
        
        self.initial_state = self.START
        self.accepting_states = {self.ACCEPT}
        
        # Safe and suspicious schemas
        self.standard_schemas = {"http", "https"}
        self.suspicious_schemas = {
            "file", "data", "javascript", "vbscript",
            "ftp", "telnet", "gopher"
        }
        
        # State-Transition Table: δ(q, σ) → q'
        # Maps (current_state, character_type) → next_state
        self.transition_table = {
            # START state: expecting alphabetic characters
            (self.START, 'alpha'): self.READING_SCHEMA,
            (self.START, 'default'): self.REJECT,
            
            # READING_SCHEMA: accumulating schema name
            (self.READING_SCHEMA, 'alpha'): self.READING_SCHEMA,
            (self.READING_SCHEMA, ':'): self.COLON,
            (self.READING_SCHEMA, 'default'): self.REJECT,
            
            # COLON: found ':' after schema
            (self.COLON, '/'): self.SLASH1,
            (self.COLON, 'default'): self.VALIDATE,  # Some schemas don't use //
            
            # SLASH1: found first '/'
            (self.SLASH1, '/'): self.SLASH2,
            (self.SLASH1, 'default'): self.REJECT,
            
            # SLASH2: found '//' - schema parsing complete
            (self.SLASH2, 'any'): self.VALIDATE,
            
            # VALIDATE: validate collected schema
            (self.VALIDATE, 'any'): self.VALIDATE,  # Terminal state
        }
    
    def _get_char_type(self, char: str) -> str:
        """Classify character for transition table lookup"""
        if char.isalpha():
            return 'alpha'
        elif char == ':':
            return ':'
        elif char == '/':
            return '/'
        else:
            return 'default'
    
    def _transition(self, state: str, char: str, schema: str = "") -> Tuple[str, str]:
        """
        Transition function δ(q, σ) → q'
        
        Input:
        - state: current state
        - char: current character
        - schema: accumulated schema string (for validation)
        
        Output:
        - (next_state, accumulated_schema)
        """
        char_type = self._get_char_type(char)
        
        # Lookup transition in table
        next_state = self.transition_table.get(
            (state, char_type),
            self.transition_table.get((state, 'default'), self.REJECT)
        )
        
        # Accumulate schema during READING_SCHEMA state
        if state == self.READING_SCHEMA and char.isalpha():
            schema += char.lower()
        
        return next_state, schema
    
    def check(self, schema: str) -> Dict:
        """
        Run DFA simulation for schema validation.
        
        Process:
        1. Initialize state to START
        2. Single while loop iterates through "schema://" string
        3. Apply transition function for each character
        4. Validate final schema string
        5. Return risk based on schema type
        """
        if not schema:
            return {
                "triggered": True,
                "state": self.REJECT,
                "reason": "URL missing protocol/schema",
                "value": None,
                "risk_score": 0.0
            }
        
        # Initialize DFA
        state = self.initial_state
        collected_schema = ""
        input_string = schema.lower() + "://"
        
        # State Transition Loop: Single while loop
        i = 0
        while i < len(input_string):
            char = input_string[i]
            state, collected_schema = self._transition(state, char, collected_schema)
            i += 1
            
            # Early termination if we reach terminal states
            if state in {self.ACCEPT, self.REJECT, self.VALIDATE}:
                break
        
        # Final validation: check collected schema
        if state == self.VALIDATE or state == self.START and collected_schema:
            if collected_schema in self.suspicious_schemas:
                state = self.ACCEPT
                triggered = True
                reason = f"Suspicious schema detected: {collected_schema}"
                risk_score = self.risk_score
            elif collected_schema in self.standard_schemas:
                state = self.REJECT
                triggered = False
                reason = f"Standard safe schema: {collected_schema}"
                risk_score = 0.0
            else:
                state = self.REJECT
                triggered = False
                reason = f"Unknown schema: {collected_schema}"
                risk_score = 0.0
        else:
            triggered = state in self.accepting_states
            reason = f"Schema validation failed - invalid format"
            risk_score = 0.0
        
        return {
            "triggered": triggered,
            "state": state,
            "reason": reason,
            "value": schema,
            "risk_score": risk_score
        }


# ========================================
# TLD DFA - State Transition Table
# ========================================

class TLDDFA:
    """
    Formal DFA for high-risk TLD detection.
    
    Mathematical Definition:
    - Q = {START, COLLECTING_TLD, LOOKUP, ACCEPT, REJECT}
    - Σ = {alphanumeric characters}
    - δ: Q × Σ → Q (transition function)
    - q0 = START
    - F = {ACCEPT, REJECT}
    
    DFA Logic:
    START → COLLECTING_TLD → LOOKUP → ACCEPT (if in high-risk list)
                                    → REJECT (if not in high-risk list)
    
    Risk Scoring:
    - ACCEPT (high-risk TLD found): risk_score = 1.0
    - REJECT (safe TLD): risk_score = 0.0
    
    High-risk TLD categories:
    1. Executable extensions: .zip, .mov, .exe, .bat, .scr
    2. Trust-building: .link, .click, .download, .online, .site
    3. Free registration: .tk, .ml, .ga, .cf, .gq, .pw
    4. Suspicious intent: .xyz, .top, .review, .faith, .loan
    """
    
    def __init__(self):
        self.risk_score = 1.0  # Weight for TLD check (highest for Layer 1)
        
        # Define States
        self.START = "START"
        self.COLLECTING_TLD = "COLLECTING_TLD"
        self.LOOKUP = "LOOKUP"
        self.ACCEPT = "ACCEPT"
        self.REJECT = "REJECT"
        
        self.initial_state = self.START
        self.accepting_states = {self.ACCEPT}
        
        # High-risk TLDs database
        self.high_risk_tlds = {
            # Executable/archive file extensions
            "zip", "mov", "exe", "bat", "scr", "app", "run",
            # Generic trust-building TLDs
            "link", "click", "download", "online", "site", "website",
            # Free/cheap registration (high abuse)
            "tk", "ml", "ga", "cf", "gq", "pw",
            # Suspicious intent
            "xyz", "top", "review", "accountant", "bid", "date",
            "faith", "loan", "men", "party", "racing", "science",
            "stream", "trade", "win", "work", "ooo"
        }
        
        # State-Transition Table: δ(q, σ) → q'
        self.transition_table = {
            # START: Begin TLD collection
            (self.START, 'alpha'): self.COLLECTING_TLD,
            (self.START, '.'): self.COLLECTING_TLD,
            (self.START, 'default'): self.REJECT,
            
            # COLLECTING_TLD: Accumulate TLD characters
            (self.COLLECTING_TLD, 'alpha'): self.COLLECTING_TLD,
            (self.COLLECTING_TLD, 'digit'): self.COLLECTING_TLD,
            (self.COLLECTING_TLD, 'hyphen'): self.COLLECTING_TLD,
            (self.COLLECTING_TLD, 'end'): self.LOOKUP,
            (self.COLLECTING_TLD, 'default'): self.LOOKUP,
            
            # LOOKUP: Check against database
            (self.LOOKUP, 'any'): self.LOOKUP,  # Terminal state
        }
    
    def _get_char_type(self, char: str, is_last: bool = False) -> str:
        """Classify character for transition table lookup"""
        if char.isalpha():
            return 'alpha'
        elif char.isdigit():
            return 'digit'
        elif char == '-':
            return 'hyphen'
        elif is_last:
            return 'end'
        else:
            return 'default'
    
    def _transition(self, state: str, char: str, is_last: bool = False) -> Tuple[str, str]:
        """
        Transition function δ(q, σ) → q'
        
        Returns:
        - (next_state, accumulated_tld)
        """
        char_type = self._get_char_type(char, is_last)
        
        # Lookup transition in table
        next_state = self.transition_table.get(
            (state, char_type),
            self.transition_table.get((state, 'default'), self.REJECT)
        )
        
        return next_state
    
    def check(self, tld: str) -> Dict:
        """
        Run DFA simulation for TLD validation.
        
        Process:
        1. Initialize state to START
        2. Single while loop iterates through TLD string
        3. Apply transition function for each character
        4. In LOOKUP state, check against high-risk database
        5. Return risk score based on lookup result
        """
        if not tld:
            return {
                "triggered": False,
                "state": self.REJECT,
                "reason": "No TLD provided",
                "value": None,
                "risk_score": 0.0
            }
        
        # Initialize DFA
        state = self.initial_state
        tld_lower = tld.lower().lstrip('.')
        
        # State Transition Loop: Single while loop
        i = 0
        while i < len(tld_lower):
            char = tld_lower[i]
            is_last = (i == len(tld_lower) - 1)
            state = self._transition(state, char, is_last)
            i += 1
        
        # Final transition to LOOKUP state
        state = self._transition(state, '', is_last=True)
        
        # Check TLD against high-risk database (final acceptance logic)
        if tld_lower in self.high_risk_tlds:
            final_state = self.ACCEPT
            triggered = True
            reason = f"High-risk TLD detected: .{tld_lower}"
            risk_score = self.risk_score
        else:
            final_state = self.REJECT
            triggered = False
            reason = f"Safe TLD: .{tld_lower}"
            risk_score = 0.0
        
        return {
            "triggered": triggered,
            "state": final_state,
            "reason": reason,
            "value": tld_lower,
            "risk_score": risk_score
        }


# ========================================
# LAYER 1 COORDINATOR
# ========================================

class Layer1:
    """
    Layer 1 DFA Coordinator: Combines three independent DFA checks.
    
    Architecture:
    - Length DFA: Detects elongated URLs
    - Schema DFA: Identifies suspicious protocols
    - TLD DFA: Flags high-risk top-level domains
    
    Risk Calculation:
    - Each DFA contributes a risk_score based on its check weight
    - Total Layer 1 risk = sum of triggered check risk_scores
    - Layer weight multiplier applied by Risk Scorer module
    
    States and Transitions:
    - Each DFA runs independently with its own state machine
    - Results aggregated for final Layer 1 assessment
    - Transparent reporting of which checks triggered
    """
    
    def __init__(self, length_threshold: int = 75):
        self.length_dfa = LengthDFA(length_threshold)
        self.schema_dfa = SchemaDFA()
        self.tld_dfa = TLDDFA()
        self.tokenizer = TokenizerDFA()
    
    def analyze(self, url: str) -> Dict:
        """
        Execute all Layer 1 DFA checks and aggregate results.
        
        Process:
        1. Tokenize URL into components
        2. Run Length DFA on full URL
        3. Run Schema DFA on protocol
        4. Run TLD DFA on top-level domain
        5. Aggregate results with risk scores
        6. Return comprehensive assessment
        """
        # Tokenize URL for component analysis
        tokens = self.tokenizer.tokenize(url)
        hostname_components = self.tokenizer.get_hostname_components(tokens["hostname"])
        
        # Run individual DFA checks
        length_check = self.length_dfa.check(url)
        schema_check = self.schema_dfa.check(tokens["schema"])
        tld_check = self.tld_dfa.check(hostname_components["tld"])
        
        # Aggregate results
        triggered_count = sum([
            length_check["triggered"],
            schema_check["triggered"],
            tld_check["triggered"]
        ])
        
        total_risk_score = sum([
            length_check.get("risk_score", 0.0),
            schema_check.get("risk_score", 0.0),
            tld_check.get("risk_score", 0.0)
        ])
        
        return {
            "layer": "Layer 1 (Basic)",
            "checks": {
                "length": length_check,
                "schema": schema_check,
                "tld": tld_check
            },
            "triggered_count": triggered_count,
            "total_checks": 3,
            "layer_risk_score": round(total_risk_score, 2)
        }

