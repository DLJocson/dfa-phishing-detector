"""
================================================================================
LAYER 1: BASIC DFA CHECKS FOR URL SECURITY
================================================================================
This module implements three Deterministic Finite Automata (DFA) for URL analysis:
    1. LengthDFA  - Detects abnormally long URLs (threshold: 75 characters)
    2. SchemaDFA  - Detects malicious protocols (data:, file:)
    3. TLDDFA     - Detects high-risk top-level domains (.zip, .exe, .mov, .tk, .xyz)

Each DFA follows the formal 5-tuple definition: M = (Q, Σ, δ, q₀, F)
    - Q  = Finite set of states
    - Σ  = Input alphabet (set of valid characters)
    - δ  = Transition function: Q × Σ → Q
    - q₀ = Initial state
    - F  = Set of accepting/final states

DESIGN PRINCIPLE: No Python shortcuts - all logic is explicit for academic presentation
================================================================================
"""

from typing import Dict, Set, Tuple


# ==============================================================================
# LENGTH DFA
# ==============================================================================
# Purpose: Detect URLs that exceed a length threshold (default: 75 characters)
# Risk Score: 0.3 (Low-Medium risk indicator)
# 
# Formal Definition:
#   Q  = {Q0_START, Q1_COUNTING, Q2_ACCEPT_SAFE, Q3_ACCEPT_ANOMALY}
#   Σ  = {All printable ASCII characters: codes 32-126}
#   δ  = See _transition() method
#   q₀ = Q0_START
#   F  = {Q2_ACCEPT_SAFE, Q3_ACCEPT_ANOMALY}
#
# State Diagram:
#   [Q0_START] --any char--> [Q1_COUNTING] --count≤threshold--> [Q1_COUNTING]
#                                         --count>threshold--> [Q3_ACCEPT_ANOMALY]
#   [Q1_COUNTING] --end of input, count≤threshold--> [Q2_ACCEPT_SAFE]
# ==============================================================================

class LengthDFA:
    """
    DFA for URL length anomaly detection.
    
    This DFA counts characters manually without using len() function.
    Each character is validated against the alphabet before counting.
    """
    
    def __init__(self, threshold: int = 75, debug: bool = False):
        """
        Initialize LengthDFA with threshold and debug settings.
        
        Args:
            threshold: Maximum acceptable URL length (default: 75)
            debug: Enable state transition tracing (default: False)
        """
        # ----------------------------------------------------------------------
        # CONFIGURATION
        # ----------------------------------------------------------------------
        self.threshold = threshold      # Maximum acceptable length
        self.risk_score = 0.3           # Risk score when triggered
        self.debug = debug              # Debug mode flag
        
        # ----------------------------------------------------------------------
        # Q: FINITE SET OF STATES
        # ----------------------------------------------------------------------
        # Q0_START: Initial state, waiting for first character
        self.Q0_START = "Q0_START"
        
        # Q1_COUNTING: Processing characters, counting length
        self.Q1_COUNTING = "Q1_COUNTING"
        
        # Q2_ACCEPT_SAFE: Final state - URL length is acceptable
        self.Q2_ACCEPT_SAFE = "Q2_ACCEPT_SAFE"
        
        # Q3_ACCEPT_ANOMALY: Final state - URL length exceeds threshold
        self.Q3_ACCEPT_ANOMALY = "Q3_ACCEPT_ANOMALY"
        
        # ----------------------------------------------------------------------
        # q₀: INITIAL STATE
        # ----------------------------------------------------------------------
        self.initial_state = self.Q0_START
        
        # ----------------------------------------------------------------------
        # F: SET OF ACCEPTING STATES
        # ----------------------------------------------------------------------
        self.accepting_states_safe = self.Q2_ACCEPT_SAFE
        self.accepting_states_anomaly = self.Q3_ACCEPT_ANOMALY
        
        # ----------------------------------------------------------------------
        # Σ: INPUT ALPHABET
        # Build alphabet manually - all printable ASCII characters (32-126)
        # ----------------------------------------------------------------------
        self.alphabet = set()
        ascii_code = 32  # Start at space character
        while ascii_code <= 126:  # End at tilde character
            character = chr(ascii_code)
            self.alphabet.add(character)
            ascii_code = ascii_code + 1  # Manual increment, no += shortcut
    
    def _is_in_alphabet(self, char: str) -> bool:
        """
        Check if character belongs to alphabet Σ.
        
        Manual ASCII range check - NO 'in' operator for set membership.
        
        Args:
            char: Single character to validate
            
        Returns:
            True if character is in alphabet, False otherwise
        """
        # Get ASCII code of character
        ascii_code = ord(char)
        
        # Check if within printable ASCII range [32, 126]
        # Using explicit comparison - no shortcuts
        if ascii_code >= 32:
            if ascii_code <= 126:
                return True
        
        return False
    
    def _transition(self, current_state: str, input_char: str, char_count: int) -> str:
        """
        Transition function δ: Q × Σ → Q
        
        This function defines how the DFA moves between states based on
        the current state and input character.
        
        Args:
            current_state: Current DFA state (element of Q)
            input_char: Current character being processed (element of Σ)
            char_count: Current character count (used for threshold comparison)
            
        Returns:
            Next state (element of Q)
        
        Transition Rules:
            δ(Q0_START, any) → Q1_COUNTING
            δ(Q1_COUNTING, any) → Q1_COUNTING if count ≤ threshold
            δ(Q1_COUNTING, any) → Q3_ACCEPT_ANOMALY if count > threshold
            δ(Q3_ACCEPT_ANOMALY, any) → Q3_ACCEPT_ANOMALY (absorbing state)
        """
        # Store next state - will be determined by transition rules
        next_state = current_state
        
        # ----------------------------------------------------------------------
        # TRANSITION RULE 1: From START state
        # δ(Q0_START, any) → Q1_COUNTING
        # First character moves us to counting state
        # ----------------------------------------------------------------------
        if current_state == self.Q0_START:
            next_state = self.Q1_COUNTING
            
            if self.debug:
                print(f"    δ({current_state}, '{input_char}') → {next_state}")
                print(f"      Reason: First character received, begin counting")
        
        # ----------------------------------------------------------------------
        # TRANSITION RULE 2: From COUNTING state
        # δ(Q1_COUNTING, any) → Q1_COUNTING OR Q3_ACCEPT_ANOMALY
        # Depends on whether count exceeds threshold
        # ----------------------------------------------------------------------
        elif current_state == self.Q1_COUNTING:
            # Manual threshold comparison - NO shortcuts
            count_exceeds_threshold = False
            if char_count > self.threshold:
                count_exceeds_threshold = True
            
            if count_exceeds_threshold:
                # Threshold exceeded - transition to anomaly state
                next_state = self.Q3_ACCEPT_ANOMALY
                
                if self.debug:
                    print(f"    δ({current_state}, '{input_char}') → {next_state}")
                    print(f"      Reason: Count ({char_count}) > Threshold ({self.threshold})")
            else:
                # Still within threshold - stay in counting state
                next_state = self.Q1_COUNTING
                
                if self.debug:
                    print(f"    δ({current_state}, '{input_char}') → {next_state}")
                    print(f"      Reason: Count ({char_count}) ≤ Threshold ({self.threshold})")
        
        # ----------------------------------------------------------------------
        # TRANSITION RULE 3: From ANOMALY state (absorbing)
        # δ(Q3_ACCEPT_ANOMALY, any) → Q3_ACCEPT_ANOMALY
        # Once in anomaly state, we stay there regardless of input
        # ----------------------------------------------------------------------
        elif current_state == self.Q3_ACCEPT_ANOMALY:
            next_state = self.Q3_ACCEPT_ANOMALY
            
            if self.debug:
                print(f"    δ({current_state}, '{input_char}') → {next_state}")
                print(f"      Reason: Absorbing state - anomaly already detected")
        
        return next_state
    
    def check(self, url: str) -> Dict:
        """
        Execute the Length DFA on input URL.
        
        This method processes the URL character by character,
        counting length manually without using len() function.
        
        Args:
            url: Input URL string to analyze
            
        Returns:
            Dictionary containing:
                - triggered: Boolean indicating if anomaly detected
                - state: Final DFA state
                - reason: Human-readable explanation
                - value: Calculated URL length
                - threshold: Threshold value used
                - risk_score: Risk score (0.0 if not triggered)
        """
        if self.debug:
            print(f"\n{'='*70}")
            print(f"LENGTH DFA EXECUTION TRACE")
            print(f"{'='*70}")
            print(f"Input URL: '{url}'")
            print(f"Threshold: {self.threshold}")
            print(f"Initial State: {self.initial_state}")
            print(f"\nProcessing Characters:")
            print(f"-" * 70)
        
        # ----------------------------------------------------------------------
        # INITIALIZE DFA
        # ----------------------------------------------------------------------
        current_state = self.initial_state
        
        # Manual character counter - NO len() function
        char_count = 0
        
        # Manual index for iteration - NO for loop
        char_index = 0
        
        # ----------------------------------------------------------------------
        # MANUAL STRING LENGTH CALCULATION
        # We need to know when to stop, but we'll count ourselves
        # This is the ONLY place we check string bounds
        # ----------------------------------------------------------------------
        url_length = 0
        temp_index = 0
        try:
            while True:
                _ = url[temp_index]  # Access character to check if exists
                url_length = url_length + 1
                temp_index = temp_index + 1
        except IndexError:
            pass  # End of string reached
        
        if self.debug:
            print(f"Manually calculated URL length: {url_length}")
            print(f"-" * 70)
        
        # ----------------------------------------------------------------------
        # PROCESS EACH CHARACTER
        # Manual iteration using while loop and index
        # ----------------------------------------------------------------------
        while char_index < url_length:
            # Get current character
            current_char = url[char_index]
            
            # Increment counter BEFORE transition (count represents position)
            char_count = char_count + 1
            
            if self.debug:
                print(f"\n  Position {char_count}:")
                print(f"    Character: '{current_char}' (ASCII: {ord(current_char)})")
            
            # ------------------------------------------------------------------
            # VALIDATE CHARACTER AGAINST ALPHABET Σ
            # ------------------------------------------------------------------
            char_is_valid = self._is_in_alphabet(current_char)
            
            if char_is_valid == False:
                if self.debug:
                    print(f"    ERROR: Character not in alphabet Σ")
                    print(f"    ASCII code {ord(current_char)} outside range [32, 126]")
                
                return {
                    "triggered": False,
                    "state": "REJECT_INVALID_CHAR",
                    "reason": f"Invalid character at position {char_count}: ASCII {ord(current_char)}",
                    "value": char_count,
                    "threshold": self.threshold,
                    "risk_score": 0.0
                }
            
            # ------------------------------------------------------------------
            # EXECUTE STATE TRANSITION
            # δ(current_state, current_char) → next_state
            # ------------------------------------------------------------------
            current_state = self._transition(current_state, current_char, char_count)
            
            # Move to next character - manual increment
            char_index = char_index + 1
        
        # ----------------------------------------------------------------------
        # DETERMINE FINAL STATE
        # If we finished counting and still in Q1_COUNTING, URL is safe
        # ----------------------------------------------------------------------
        if current_state == self.Q1_COUNTING:
            current_state = self.Q2_ACCEPT_SAFE
            
            if self.debug:
                print(f"\n  End of input reached while in Q1_COUNTING")
                print(f"  Transitioning to final safe state: {self.Q2_ACCEPT_SAFE}")
        
        # ----------------------------------------------------------------------
        # DETERMINE IF ANOMALY WAS TRIGGERED
        # Manual state comparison - NO 'in' operator
        # ----------------------------------------------------------------------
        triggered = False
        if current_state == self.Q3_ACCEPT_ANOMALY:
            triggered = True
        
        # ----------------------------------------------------------------------
        # BUILD RESULT
        # ----------------------------------------------------------------------
        risk_score_result = 0.0
        reason_text = ""
        
        if triggered:
            risk_score_result = self.risk_score
            reason_text = f"URL length ({char_count}) exceeds threshold ({self.threshold})"
        else:
            risk_score_result = 0.0
            reason_text = f"URL length ({char_count}) is acceptable"
        
        if self.debug:
            print(f"\n{'='*70}")
            print(f"FINAL RESULT")
            print(f"{'='*70}")
            print(f"Final State: {current_state}")
            print(f"Total Characters Counted: {char_count}")
            print(f"Threshold: {self.threshold}")
            print(f"Triggered: {triggered}")
            print(f"Risk Score: {risk_score_result}")
            print(f"{'='*70}\n")
        
        return {
            "triggered": triggered,
            "state": current_state,
            "reason": reason_text,
            "value": char_count,
            "threshold": self.threshold,
            "risk_score": risk_score_result
        }


# ==============================================================================
# SCHEMA DFA
# ==============================================================================
# Purpose: Detect malicious URL schemas/protocols (data:, file:)
# Risk Score: 0.8 (High risk indicator)
#
# Formal Definition:
#   Q  = {Q0_START, Q1_H, Q2_HT, Q3_HTT, Q4_HTTP, Q5_HTTPS,
#         Q6_D, Q7_DA, Q8_DAT, Q9_DATA,
#         Q10_F, Q11_FI, Q12_FIL, Q13_FILE,
#         SAFE_HTTP, SAFE_HTTPS, MALICIOUS_DATA, MALICIOUS_FILE, REJECT}
#   Σ  = {a-z, A-Z, :} (letters and colon)
#   δ  = Defined in transition table self.delta
#   q₀ = Q0_START
#   F  = {MALICIOUS_DATA, MALICIOUS_FILE} (accepting = malicious detected)
#
# State Diagram (simplified):
#   START --h/H--> Q1 --t/T--> Q2 --t/T--> Q3 --p/P--> Q4 --:--> SAFE_HTTP
#                                                       |--s/S--> Q5 --:--> SAFE_HTTPS
#   START --d/D--> Q6 --a/A--> Q7 --t/T--> Q8 --a/A--> Q9 --:--> MALICIOUS_DATA
#   START --f/F--> Q10 --i/I--> Q11 --l/L--> Q12 --e/E--> Q13 --:--> MALICIOUS_FILE
# ==============================================================================

class SchemaDFA:
    """
    Table-Driven DFA for URL schema/protocol validation.
    
    This DFA uses a transition table (dictionary) to determine state changes.
    Both uppercase and lowercase letters are handled explicitly in the table.
    NO .lower() or any string manipulation shortcuts are used.
    """
    
    def __init__(self, debug: bool = False):
        """
        Initialize SchemaDFA with transition table and states.
        
        Args:
            debug: Enable state transition tracing (default: False)
        """
        # ----------------------------------------------------------------------
        # CONFIGURATION
        # ----------------------------------------------------------------------
        self.risk_score = 0.8   # Risk score when malicious schema detected
        self.debug = debug      # Debug mode flag
        
        # ----------------------------------------------------------------------
        # Q: FINITE SET OF STATES
        # ----------------------------------------------------------------------
        # Initial state
        self.Q0_START = "Q0_START"
        
        # HTTP path states: h → t → t → p → [s] → :
        self.Q1_H = "Q1_H"          # Seen: h
        self.Q2_HT = "Q2_HT"        # Seen: ht
        self.Q3_HTT = "Q3_HTT"      # Seen: htt
        self.Q4_HTTP = "Q4_HTTP"    # Seen: http
        self.Q5_HTTPS = "Q5_HTTPS"  # Seen: https
        
        # DATA path states: d → a → t → a → :
        self.Q6_D = "Q6_D"          # Seen: d
        self.Q7_DA = "Q7_DA"        # Seen: da
        self.Q8_DAT = "Q8_DAT"      # Seen: dat
        self.Q9_DATA = "Q9_DATA"    # Seen: data
        
        # FILE path states: f → i → l → e → :
        self.Q10_F = "Q10_F"        # Seen: f
        self.Q11_FI = "Q11_FI"      # Seen: fi
        self.Q12_FIL = "Q12_FIL"    # Seen: fil
        self.Q13_FILE = "Q13_FILE"  # Seen: file
        
        # Final/Terminal states
        self.SAFE_HTTP = "SAFE_HTTP"            # Safe: http:
        self.SAFE_HTTPS = "SAFE_HTTPS"          # Safe: https:
        self.MALICIOUS_DATA = "MALICIOUS_DATA"  # Malicious: data:
        self.MALICIOUS_FILE = "MALICIOUS_FILE"  # Malicious: file:
        self.REJECT = "REJECT"                  # Invalid/Unknown schema
        
        # ----------------------------------------------------------------------
        # q₀: INITIAL STATE
        # ----------------------------------------------------------------------
        self.initial_state = self.Q0_START
        
        # ----------------------------------------------------------------------
        # F: ACCEPTING STATES (malicious schemas)
        # ----------------------------------------------------------------------
        # Note: We consider malicious schemas as "accepting" because
        # the DFA's purpose is to DETECT them
        self.accepting_states_malicious = {self.MALICIOUS_DATA, self.MALICIOUS_FILE}
        self.accepting_states_safe = {self.SAFE_HTTP, self.SAFE_HTTPS}
        
        # ----------------------------------------------------------------------
        # δ: TRANSITION TABLE
        # Format: (current_state, input_character) → next_state
        # 
        # IMPORTANT: Both uppercase and lowercase are defined explicitly
        # NO .lower() conversion is used
        # ----------------------------------------------------------------------
        self.delta = {
            # ==================================================================
            # FROM Q0_START: Branch based on first character
            # ==================================================================
            # Lowercase
            (self.Q0_START, 'h'): self.Q1_H,    # Start of http/https
            (self.Q0_START, 'd'): self.Q6_D,    # Start of data
            (self.Q0_START, 'f'): self.Q10_F,   # Start of file
            # Uppercase
            (self.Q0_START, 'H'): self.Q1_H,    # Start of HTTP/HTTPS
            (self.Q0_START, 'D'): self.Q6_D,    # Start of DATA
            (self.Q0_START, 'F'): self.Q10_F,   # Start of FILE
            
            # ==================================================================
            # HTTP/HTTPS PATH: h/H → t/T → t/T → p/P → [s/S] → :
            # ==================================================================
            # Q1_H: Seen 'h', expecting 't'
            (self.Q1_H, 't'): self.Q2_HT,
            (self.Q1_H, 'T'): self.Q2_HT,
            
            # Q2_HT: Seen 'ht', expecting 't'
            (self.Q2_HT, 't'): self.Q3_HTT,
            (self.Q2_HT, 'T'): self.Q3_HTT,
            
            # Q3_HTT: Seen 'htt', expecting 'p'
            (self.Q3_HTT, 'p'): self.Q4_HTTP,
            (self.Q3_HTT, 'P'): self.Q4_HTTP,
            
            # Q4_HTTP: Seen 'http', expecting ':' or 's'
            (self.Q4_HTTP, ':'): self.SAFE_HTTP,    # http: is safe
            (self.Q4_HTTP, 's'): self.Q5_HTTPS,     # Continue to https
            (self.Q4_HTTP, 'S'): self.Q5_HTTPS,     # Continue to HTTPS
            
            # Q5_HTTPS: Seen 'https', expecting ':'
            (self.Q5_HTTPS, ':'): self.SAFE_HTTPS,  # https: is safe
            
            # ==================================================================
            # DATA PATH: d/D → a/A → t/T → a/A → :
            # ==================================================================
            # Q6_D: Seen 'd', expecting 'a'
            (self.Q6_D, 'a'): self.Q7_DA,
            (self.Q6_D, 'A'): self.Q7_DA,
            
            # Q7_DA: Seen 'da', expecting 't'
            (self.Q7_DA, 't'): self.Q8_DAT,
            (self.Q7_DA, 'T'): self.Q8_DAT,
            
            # Q8_DAT: Seen 'dat', expecting 'a'
            (self.Q8_DAT, 'a'): self.Q9_DATA,
            (self.Q8_DAT, 'A'): self.Q9_DATA,
            
            # Q9_DATA: Seen 'data', expecting ':'
            (self.Q9_DATA, ':'): self.MALICIOUS_DATA,  # data: is MALICIOUS
            
            # ==================================================================
            # FILE PATH: f/F → i/I → l/L → e/E → :
            # ==================================================================
            # Q10_F: Seen 'f', expecting 'i'
            (self.Q10_F, 'i'): self.Q11_FI,
            (self.Q10_F, 'I'): self.Q11_FI,
            
            # Q11_FI: Seen 'fi', expecting 'l'
            (self.Q11_FI, 'l'): self.Q12_FIL,
            (self.Q11_FI, 'L'): self.Q12_FIL,
            
            # Q12_FIL: Seen 'fil', expecting 'e'
            (self.Q12_FIL, 'e'): self.Q13_FILE,
            (self.Q12_FIL, 'E'): self.Q13_FILE,
            
            # Q13_FILE: Seen 'file', expecting ':'
            (self.Q13_FILE, ':'): self.MALICIOUS_FILE,  # file: is MALICIOUS
        }
    
    def _lookup_transition(self, current_state: str, input_char: str) -> str:
        """
        Look up next state in transition table.

        Manual dictionary lookup without using .get() or 'in'.
        """
        transition_key = (current_state, input_char)

        # Build list of keys without using 'in'
        keys_list = list(self.delta.keys())

        idx = 0
        key_found = False

        # Manual scan over keys list using index
        while idx < len(keys_list):
            key = keys_list[idx]
            key_state = key[0]
            key_char = key[1]

            if key_state == current_state:
                if key_char == input_char:
                    key_found = True
                    break

            idx = idx + 1

        if key_found:
            return self.delta[transition_key]
        else:
            return self.REJECT
    
    def check(self, schema: str) -> Dict:
        """
        Execute the Schema DFA on input schema string.
        
        Processes schema character by character using transition table.
        NO .lower() or string manipulation shortcuts used.
        
        Args:
            schema: Input schema/protocol string (e.g., "https:")
            
        Returns:
            Dictionary containing:
                - triggered: Boolean indicating if malicious schema detected
                - state: Final DFA state
                - reason: Human-readable explanation
                - value: Original schema value
                - risk_score: Risk score (0.0 if not triggered)
        """
        # ----------------------------------------------------------------------
        # HANDLE EMPTY INPUT
        # ----------------------------------------------------------------------
        if not schema:
            return {
                "triggered": False,
                "state": self.REJECT,
                "reason": "URL missing protocol/schema",
                "value": None,
                "risk_score": 0.0
            }
        
        if self.debug:
            print(f"\n{'='*70}")
            print(f"SCHEMA DFA EXECUTION TRACE")
            print(f"{'='*70}")
            print(f"Input Schema: '{schema}'")
            print(f"Initial State: {self.initial_state}")
            print(f"\nTransition Table Lookups:")
            print(f"-" * 70)
        
        # ----------------------------------------------------------------------
        # INITIALIZE DFA
        # ----------------------------------------------------------------------
        current_state = self.initial_state
        detected_schema = ""
        
        # Manual string length calculation - NO len()
        schema_length = 0
        temp_idx = 0
        try:
            while True:
                _ = schema[temp_idx]
                schema_length = schema_length + 1
                temp_idx = temp_idx + 1
        except IndexError:
            pass
        
        # Manual index for iteration
        char_index = 0
        
        # ----------------------------------------------------------------------
        # PROCESS EACH CHARACTER
        # ----------------------------------------------------------------------
        while char_index < schema_length:
            # Get current character
            current_char = schema[char_index]
            previous_state = current_state
            
            if self.debug:
                print(f"\n  Position {char_index}:")
                print(f"    Current State: {current_state}")
                print(f"    Input Character: '{current_char}'")
            
            # ------------------------------------------------------------------
            # EXECUTE TRANSITION
            # Look up δ(current_state, current_char) in transition table
            # ------------------------------------------------------------------
            current_state = self._lookup_transition(current_state, current_char)
            
            # Append character to detected schema (manual concatenation)
            detected_schema = detected_schema + current_char
            
            if self.debug:
                print(f"    Transition: δ({previous_state}, '{current_char}') → {current_state}")
            
            # Check if we hit REJECT state
            if current_state == self.REJECT:
                if self.debug:
                    print(f"    REJECTED: No valid transition exists")
                break
            
            # Move to next character
            char_index = char_index + 1
        
        # ----------------------------------------------------------------------
        # DETERMINE RESULT BASED ON FINAL STATE
        # Manual state comparison - NO 'in' operator for set membership
        # ----------------------------------------------------------------------
        triggered = False
        risk_score_result = 0.0
        reason_text = ""
        
        # Check if final state is MALICIOUS_DATA
        if current_state == self.MALICIOUS_DATA:
            triggered = True
            risk_score_result = self.risk_score
            reason_text = f"Malicious schema detected: data: (state path: {detected_schema})"
        
        # Check if final state is MALICIOUS_FILE
        elif current_state == self.MALICIOUS_FILE:
            triggered = True
            risk_score_result = self.risk_score
            reason_text = f"Malicious schema detected: file: (state path: {detected_schema})"
        
        # Check if final state is SAFE_HTTP
        elif current_state == self.SAFE_HTTP:
            triggered = False
            risk_score_result = 0.0
            reason_text = f"Safe schema detected: http: (state path: {detected_schema})"
        
        # Check if final state is SAFE_HTTPS
        elif current_state == self.SAFE_HTTPS:
            triggered = False
            risk_score_result = 0.0
            reason_text = f"Safe schema detected: https: (state path: {detected_schema})"
        
        # Any other state (including REJECT)
        else:
            triggered = False
            risk_score_result = 0.0
            reason_text = f"Unknown/Invalid schema - final state: {current_state}"
        
        if self.debug:
            print(f"\n{'='*70}")
            print(f"FINAL RESULT")
            print(f"{'='*70}")
            print(f"Final State: {current_state}")
            print(f"Detected Schema: '{detected_schema}'")
            print(f"Triggered: {triggered}")
            print(f"Risk Score: {risk_score_result}")
            print(f"{'='*70}\n")
        
        return {
            "triggered": triggered,
            "state": current_state,
            "reason": reason_text,
            "value": schema,
            "risk_score": risk_score_result
        }


# ==============================================================================
# TLD DFA
# ==============================================================================
# Purpose: Detect high-risk Top-Level Domains (.zip, .exe, .mov, .tk, .xyz)
# Risk Score: 1.0 (Critical risk indicator)
#
# Formal Definition:
#   Q  = {Q0_START, Q_DOT_SKIP,
#         Q1_Z, Q2_ZI, Q3_ZIP,
#         Q4_E, Q5_EX, Q6_EXE,
#         Q7_M, Q8_MO, Q9_MOV,
#         Q10_T, Q11_TK,
#         Q12_X, Q13_XY, Q14_XYZ,
#         MALICIOUS, SAFE, REJECT}
#   Σ  = {a-z, A-Z, .} (letters and dot)
#   δ  = Defined in transition table self.delta
#   q₀ = Q0_START
#   F  = {MALICIOUS} (accepting = high-risk TLD detected)
#
# State Diagram (simplified):
#   START --.--> DOT_SKIP (handles leading dots manually)
#   DOT_SKIP/START --z/Z--> Q1 --i/I--> Q2 --p/P--> Q3 --END--> MALICIOUS
#   DOT_SKIP/START --e/E--> Q4 --x/X--> Q5 --e/E--> Q6 --END--> MALICIOUS
#   etc.
# ==============================================================================

class TLDDFA:
    """
    Table-Driven DFA for high-risk TLD detection.
    
    This DFA detects TLDs that are commonly abused for phishing:
    .zip, .exe, .mov, .tk, .xyz
    
    Leading dots are handled through a dedicated DOT_SKIP state,
    NOT through .lstrip() or any string manipulation.
    """
    
    def __init__(self, debug: bool = False):
        """
        Initialize TLDDFA with transition table and states.
        
        Args:
            debug: Enable state transition tracing (default: False)
        """
        # ----------------------------------------------------------------------
        # CONFIGURATION
        # ----------------------------------------------------------------------
        self.risk_score = 1.0   # Risk score when high-risk TLD detected
        self.debug = debug      # Debug mode flag
        
        # ----------------------------------------------------------------------
        # Q: FINITE SET OF STATES
        # ----------------------------------------------------------------------
        # Initial and dot-handling states
        self.Q0_START = "Q0_START"      # Initial state
        self.Q_DOT_SKIP = "Q_DOT_SKIP"  # State for handling leading dots
        
        # ZIP path states: z → i → p
        self.Q1_Z = "Q1_Z"      # Seen: z
        self.Q2_ZI = "Q2_ZI"    # Seen: zi
        self.Q3_ZIP = "Q3_ZIP"  # Seen: zip (complete)
        
        # EXE path states: e → x → e
        self.Q4_E = "Q4_E"      # Seen: e
        self.Q5_EX = "Q5_EX"    # Seen: ex
        self.Q6_EXE = "Q6_EXE"  # Seen: exe (complete)
        
        # MOV path states: m → o → v
        self.Q7_M = "Q7_M"      # Seen: m
        self.Q8_MO = "Q8_MO"    # Seen: mo
        self.Q9_MOV = "Q9_MOV"  # Seen: mov (complete)
        
        # TK path states: t → k
        self.Q10_T = "Q10_T"    # Seen: t
        self.Q11_TK = "Q11_TK"  # Seen: tk (complete)
        
        # XYZ path states: x → y → z
        self.Q12_X = "Q12_X"      # Seen: x
        self.Q13_XY = "Q13_XY"    # Seen: xy
        self.Q14_XYZ = "Q14_XYZ"  # Seen: xyz (complete)
        
        # Final/Terminal states
        self.MALICIOUS = "MALICIOUS"  # High-risk TLD detected
        self.SAFE = "SAFE"            # Safe/Unknown TLD
        self.REJECT = "REJECT"        # Invalid transition
        
        # ----------------------------------------------------------------------
        # q₀: INITIAL STATE
        # ----------------------------------------------------------------------
        self.initial_state = self.Q0_START
        
        # ----------------------------------------------------------------------
        # F: ACCEPTING STATES (high-risk TLDs)
        # ----------------------------------------------------------------------
        self.accepting_state = self.MALICIOUS
        
        # ----------------------------------------------------------------------
        # STATES THAT BECOME MALICIOUS WHEN INPUT ENDS
        # These are the "complete TLD" states
        # ----------------------------------------------------------------------
        self.complete_tld_states = {
            self.Q3_ZIP,   # .zip complete
            self.Q6_EXE,   # .exe complete
            self.Q9_MOV,   # .mov complete
            self.Q11_TK,   # .tk complete
            self.Q14_XYZ   # .xyz complete
        }
        
        # ----------------------------------------------------------------------
        # δ: TRANSITION TABLE
        # Format: (current_state, input_character) → next_state
        # 
        # IMPORTANT: Both uppercase and lowercase are defined explicitly
        # NO .lower() conversion is used
        # Leading dots handled through Q_DOT_SKIP state
        # ----------------------------------------------------------------------
        self.delta = {
            # ==================================================================
            # DOT HANDLING: Manual skip of leading dots
            # ==================================================================
            (self.Q0_START, '.'): self.Q_DOT_SKIP,      # First dot
            (self.Q_DOT_SKIP, '.'): self.Q_DOT_SKIP,    # Additional dots (stay)
            
            # ==================================================================
            # FROM Q0_START: Branch based on first letter (lowercase)
            # ==================================================================
            (self.Q0_START, 'z'): self.Q1_Z,
            (self.Q0_START, 'e'): self.Q4_E,
            (self.Q0_START, 'm'): self.Q7_M,
            (self.Q0_START, 't'): self.Q10_T,
            (self.Q0_START, 'x'): self.Q12_X,
            
            # FROM Q0_START: Branch based on first letter (UPPERCASE)
            (self.Q0_START, 'Z'): self.Q1_Z,
            (self.Q0_START, 'E'): self.Q4_E,
            (self.Q0_START, 'M'): self.Q7_M,
            (self.Q0_START, 'T'): self.Q10_T,
            (self.Q0_START, 'X'): self.Q12_X,
            
            # ==================================================================
            # FROM Q_DOT_SKIP: Same transitions as Q0_START for letters
            # ==================================================================
            (self.Q_DOT_SKIP, 'z'): self.Q1_Z,
            (self.Q_DOT_SKIP, 'e'): self.Q4_E,
            (self.Q_DOT_SKIP, 'm'): self.Q7_M,
            (self.Q_DOT_SKIP, 't'): self.Q10_T,
            (self.Q_DOT_SKIP, 'x'): self.Q12_X,
            
            (self.Q_DOT_SKIP, 'Z'): self.Q1_Z,
            (self.Q_DOT_SKIP, 'E'): self.Q4_E,
            (self.Q_DOT_SKIP, 'M'): self.Q7_M,
            (self.Q_DOT_SKIP, 'T'): self.Q10_T,
            (self.Q_DOT_SKIP, 'X'): self.Q12_X,
            
            # ==================================================================
            # ZIP PATH: z/Z → i/I → p/P
            # ==================================================================
            (self.Q1_Z, 'i'): self.Q2_ZI,
            (self.Q1_Z, 'I'): self.Q2_ZI,
            (self.Q2_ZI, 'p'): self.Q3_ZIP,
            (self.Q2_ZI, 'P'): self.Q3_ZIP,
            
            # ==================================================================
            # EXE PATH: e/E → x/X → e/E
            # ==================================================================
            (self.Q4_E, 'x'): self.Q5_EX,
            (self.Q4_E, 'X'): self.Q5_EX,
            (self.Q5_EX, 'e'): self.Q6_EXE,
            (self.Q5_EX, 'E'): self.Q6_EXE,
            
            # ==================================================================
            # MOV PATH: m/M → o/O → v/V
            # ==================================================================
            (self.Q7_M, 'o'): self.Q8_MO,
            (self.Q7_M, 'O'): self.Q8_MO,
            (self.Q8_MO, 'v'): self.Q9_MOV,
            (self.Q8_MO, 'V'): self.Q9_MOV,
            
            # ==================================================================
            # TK PATH: t/T → k/K
            # ==================================================================
            (self.Q10_T, 'k'): self.Q11_TK,
            (self.Q10_T, 'K'): self.Q11_TK,
            
            # ==================================================================
            # XYZ PATH: x/X → y/Y → z/Z
            # ==================================================================
            (self.Q12_X, 'y'): self.Q13_XY,
            (self.Q12_X, 'Y'): self.Q13_XY,
            (self.Q13_XY, 'z'): self.Q14_XYZ,
            (self.Q13_XY, 'Z'): self.Q14_XYZ,
        }
    
    def _lookup_transition(self, current_state: str, input_char: str) -> str:
        """
        Look up next state in transition table.

        Manual dictionary lookup without using .get() or 'in'.
        """
        transition_key = (current_state, input_char)

        # Build list of keys without using 'in'
        keys_list = list(self.delta.keys())

        idx = 0
        key_found = False

        # Manual scan over keys list using index
        while idx < len(keys_list):
            key = keys_list[idx]
            key_state = key[0]
            key_char = key[1]

            if key_state == current_state:
                if key_char == input_char:
                    key_found = True
                    break

            idx = idx + 1

        if key_found:
            return self.delta[transition_key]
        else:
            return self.REJECT
    
    def _is_complete_tld_state(self, state: str) -> bool:
        """
        Check if state represents a complete high-risk TLD.
        
        Manual set membership check - NO 'in' operator.
        
        Args:
            state: State to check
            
        Returns:
            True if state is a complete TLD state, False otherwise
        """
        # Check each complete TLD state manually
        if state == self.Q3_ZIP:
            return True
        if state == self.Q6_EXE:
            return True
        if state == self.Q9_MOV:
            return True
        if state == self.Q11_TK:
            return True
        if state == self.Q14_XYZ:
            return True
        
        return False
    
    def check(self, tld: str) -> Dict:
        """
        Execute the TLD DFA on input TLD string.
        
        Processes TLD character by character using transition table.
        Leading dots are handled through Q_DOT_SKIP state, NOT .lstrip().
        
        Args:
            tld: Input TLD string (e.g., ".zip" or "zip")
            
        Returns:
            Dictionary containing:
                - triggered: Boolean indicating if high-risk TLD detected
                - state: Final DFA state
                - reason: Human-readable explanation
                - value: TLD value (without leading dot)
                - risk_score: Risk score (0.0 if not triggered)
        """
        # ----------------------------------------------------------------------
        # HANDLE EMPTY INPUT
        # ----------------------------------------------------------------------
        if not tld:
            return {
                "triggered": False,
                "state": self.REJECT,
                "reason": "No TLD provided",
                "value": None,
                "risk_score": 0.0
            }
        
        if self.debug:
            print(f"\n{'='*70}")
            print(f"TLD DFA EXECUTION TRACE")
            print(f"{'='*70}")
            print(f"Input TLD: '{tld}'")
            print(f"Initial State: {self.initial_state}")
            print(f"\nTransition Table Lookups:")
            print(f"-" * 70)
        
        # ----------------------------------------------------------------------
        # INITIALIZE DFA
        # ----------------------------------------------------------------------
        current_state = self.initial_state
        detected_tld = ""
        
        # Manual string length calculation - NO len()
        tld_length = 0
        temp_idx = 0
        try:
            while True:
                _ = tld[temp_idx]
                tld_length = tld_length + 1
                temp_idx = temp_idx + 1
        except IndexError:
            pass
        
        # Manual index for iteration
        char_index = 0
        
        # ----------------------------------------------------------------------
        # PROCESS EACH CHARACTER
        # ----------------------------------------------------------------------
        while char_index < tld_length:
            # Get current character
            current_char = tld[char_index]
            previous_state = current_state
            
            if self.debug:
                print(f"\n  Position {char_index}:")
                print(f"    Current State: {current_state}")
                print(f"    Input Character: '{current_char}'")
            
            # ------------------------------------------------------------------
            # EXECUTE TRANSITION
            # Look up δ(current_state, current_char) in transition table
            # ------------------------------------------------------------------
            current_state = self._lookup_transition(current_state, current_char)
            
            # Build detected_tld (skip dots in the output)
            if current_char != '.':
                detected_tld = detected_tld + current_char
            
            if self.debug:
                print(f"    Transition: δ({previous_state}, '{current_char}') → {current_state}")
            
            # Check if we hit REJECT state
            if current_state == self.REJECT:
                if self.debug:
                    print(f"    Result: No valid transition - TLD not in high-risk list")
                break
            
            # Move to next character
            char_index = char_index + 1
        
        # ----------------------------------------------------------------------
        # DETERMINE FINAL STATE
        # If we ended in a "complete TLD" state, it's MALICIOUS
        # If we ended in REJECT, it's SAFE (not a high-risk TLD)
        # ----------------------------------------------------------------------
        is_complete = self._is_complete_tld_state(current_state)
        
        if is_complete:
            current_state = self.MALICIOUS
            if self.debug:
                print(f"\n  End of input in complete TLD state")
                print(f"  Transitioning to: {self.MALICIOUS}")
        elif current_state != self.REJECT:
            # Partial match but not complete - treat as safe
            current_state = self.SAFE
            if self.debug:
                print(f"\n  End of input in partial state")
                print(f"  Transitioning to: {self.SAFE}")
        
        # ----------------------------------------------------------------------
        # DETERMINE RESULT BASED ON FINAL STATE
        # ----------------------------------------------------------------------
        triggered = False
        risk_score_result = 0.0
        reason_text = ""
        
        if current_state == self.MALICIOUS:
            triggered = True
            risk_score_result = self.risk_score
            reason_text = f"High-risk TLD detected: .{detected_tld}"
        elif current_state == self.SAFE:
            triggered = False
            risk_score_result = 0.0
            reason_text = f"Safe TLD: .{detected_tld}"
        else:  # REJECT
            triggered = False
            risk_score_result = 0.0
            reason_text = f"Unknown TLD (not in high-risk list): .{detected_tld}"
        
        if self.debug:
            print(f"\n{'='*70}")
            print(f"FINAL RESULT")
            print(f"{'='*70}")
            print(f"Final State: {current_state}")
            print(f"Detected TLD: '.{detected_tld}'")
            print(f"Triggered: {triggered}")
            print(f"Risk Score: {risk_score_result}")
            print(f"{'='*70}\n")
        
        return {
            "triggered": triggered,
            "state": current_state,
            "reason": reason_text,
            "value": detected_tld,
            "risk_score": risk_score_result
        }


# ==============================================================================
# LAYER 1 COORDINATOR
# ==============================================================================
# Purpose: Orchestrate all Layer 1 DFA checks and aggregate results
# 
# This class combines:
#   1. LengthDFA - URL length anomaly detection
#   2. SchemaDFA - Malicious protocol detection  
#   3. TLDDFA - High-risk TLD detection
#
# Total possible risk score: 0.3 + 0.8 + 1.0 = 2.1
# ==============================================================================

class Layer1:
    """
    Layer 1 coordinator: combines Length, Schema, and TLD DFA checks.
    
    This class orchestrates all three basic DFA checks and aggregates
    their results into a single layer report.
    """
    
    def __init__(self, length_threshold: int = 75, debug: bool = False):
        """
        Initialize Layer 1 with all three DFAs.
        
        Args:
            length_threshold: Maximum acceptable URL length (default: 75)
            debug: Enable state transition tracing for all DFAs
        """
        self.debug = debug
        
        # Initialize individual DFAs
        self.length_dfa = LengthDFA(threshold=length_threshold, debug=debug)
        self.schema_dfa = SchemaDFA(debug=debug)
        self.tld_dfa = TLDDFA(debug=debug)
        
        # Import tokenizer for URL parsing
        from .tokenizer import TokenizerDFA
        self.tokenizer = TokenizerDFA()
    
    def analyze(self, url: str) -> Dict:
        """
        Execute all Layer 1 DFA checks and aggregate results.
        
        This method:
        1. Tokenizes the URL to extract schema, hostname, TLD
        2. Runs each DFA check independently
        3. Aggregates results with manual counting (NO sum())
        
        Args:
            url: Input URL to analyze
            
        Returns:
            Dictionary containing:
                - layer: Layer identifier
                - checks: Individual check results
                - triggered_count: Number of checks that triggered
                - total_checks: Total number of checks (3)
                - layer_risk_score: Sum of risk scores
        """
        if self.debug:
            print(f"\n{'#'*70}")
            print(f"# LAYER 1 ANALYSIS START")
            print(f"{'#'*70}")
            print(f"URL: {url}")
        
        # ----------------------------------------------------------------------
        # TOKENIZE URL
        # Extract components for individual DFA checks
        # ----------------------------------------------------------------------
        tokens = self.tokenizer.tokenize(url)
        hostname_components = self.tokenizer.get_hostname_components(tokens["hostname"])
        
        if self.debug:
            print(f"\nTokenized URL:")
            print(f"  Schema: {tokens['schema']}")
            print(f"  Hostname: {tokens['hostname']}")
            print(f"  TLD: {hostname_components['tld']}")
        
        # ----------------------------------------------------------------------
        # EXECUTE DFA CHECKS
        # ----------------------------------------------------------------------
        length_result = self.length_dfa.check(url)
        schema_result = self.schema_dfa.check(tokens["schema"])
        tld_result = self.tld_dfa.check(hostname_components["tld"])
        
        # ----------------------------------------------------------------------
        # COUNT TRIGGERED CHECKS
        # Manual counting - NO sum() function
        # ----------------------------------------------------------------------
        triggered_count = 0
        
        # Check length result
        if length_result["triggered"] == True:
            triggered_count = triggered_count + 1
        
        # Check schema result
        if schema_result["triggered"] == True:
            triggered_count = triggered_count + 1
        
        # Check TLD result
        if tld_result["triggered"] == True:
            triggered_count = triggered_count + 1
        
        # ----------------------------------------------------------------------
        # CALCULATE TOTAL RISK SCORE
        # Manual risk summation - NO sum()
        total_risk_score = 0.0

        try:
            length_risk = length_result["risk_score"]
        except KeyError:
            length_risk = 0.0
        total_risk_score = total_risk_score + length_risk

        try:
            schema_risk = schema_result["risk_score"]
        except KeyError:
            schema_risk = 0.0
        total_risk_score = total_risk_score + schema_risk

        try:
            tld_risk = tld_result["risk_score"]
        except KeyError:
            tld_risk = 0.0
        total_risk_score = total_risk_score + tld_risk

        # NOTE: No round() used (per "no shortcuts")
        
        if self.debug:
            print(f"\n{'#'*70}")
            print(f"# LAYER 1 ANALYSIS COMPLETE")
            print(f"{'#'*70}")
            print(f"Triggered Checks: {triggered_count}/3")
            print(f"  - Length DFA: {length_result['triggered']}")
            print(f"  - Schema DFA: {schema_result['triggered']}")
            print(f"  - TLD DFA: {tld_result['triggered']}")
            print(f"Total Risk Score: {total_risk_score}")
            print(f"{'#'*70}\n")
        
        return {
            "layer": "Layer 1 (Basic)",
            "checks": {
                "length": length_result,
                "schema": schema_result,
                "tld": tld_result
            },
            "triggered_count": triggered_count,
            "total_checks": 3,
            "layer_risk_score": total_risk_score
        }