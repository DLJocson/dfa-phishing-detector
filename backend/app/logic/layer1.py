"""Layer 1: Basic DFA checks for URL security (Length, Schema, TLD)"""

from typing import Dict, Tuple
from .tokenizer import TokenizerDFA


class LengthDFA:
    """DFA for URL length anomaly detection (threshold: 75 characters)"""
    
    def __init__(self, threshold: int = 75):
        self.threshold = threshold
        self.risk_score = 0.3
        self.START = "START"
        self.CHECKING = "CHECKING"
        self.ACCEPT = "ACCEPT"
        self.REJECT = "REJECT"
        self.initial_state = self.START
        self.accepting_states = {self.ACCEPT}
    
    def _transition(self, state: str, char_count: int) -> str:
        """Transition function δ(q, σ) → q'"""
        if state == self.START:
            return self.CHECKING
        elif state == self.CHECKING:
            if char_count > self.threshold:
                return self.ACCEPT
            else:
                return self.CHECKING
        else:
            return state
    
    def check(self, url: str) -> Dict:
        """Execute DFA and return risk assessment"""
        state = self.initial_state
        length = len(url)
        
        i = 0
        while i < len(url):
            char_count = i + 1
            state = self._transition(state, char_count)
            i += 1
        
        state = self._transition(state, length)
        triggered = state in self.accepting_states
        
        return {
            "triggered": triggered,
            "state": state,
            "reason": f"URL length ({length}) exceeds threshold ({self.threshold})" if triggered else f"URL length ({length}) is acceptable",
            "value": length,
            "threshold": self.threshold,
            "risk_score": self.risk_score if triggered else 0.0
        }


class SchemaDFA:
    """Table-Driven DFA for protocol/schema validation using pure state transitions"""
    
    def __init__(self, debug=False):
        self.risk_score = 0.8
        self.debug = debug
        
        # Define states - each character in target schemas gets its own state
        self.Q0_START = "Q0_START"
        
        # States for "http" path
        self.Q1_H = "Q1_H"
        self.Q2_HT = "Q2_HT"
        self.Q3_HTT = "Q3_HTT"
        self.Q4_HTTP = "Q4_HTTP"
        
        # States for "https" path (branches from Q4_HTTP)
        self.Q5_HTTPS = "Q5_HTTPS"
        
        # States for "data" path
        self.Q6_D = "Q6_D"
        self.Q7_DA = "Q7_DA"
        self.Q8_DAT = "Q8_DAT"
        self.Q9_DATA = "Q9_DATA"
        
        # States for "file" path
        self.Q10_F = "Q10_F"
        self.Q11_FI = "Q11_FI"
        self.Q12_FIL = "Q12_FIL"
        self.Q13_FILE = "Q13_FILE"
        
        # Final states
        self.SAFE_HTTP = "SAFE_HTTP"
        self.SAFE_HTTPS = "SAFE_HTTPS"
        self.MALICIOUS_DATA = "MALICIOUS_DATA"
        self.MALICIOUS_FILE = "MALICIOUS_FILE"
        self.REJECT = "REJECT"
        
        self.initial_state = self.Q0_START
        self.accepting_states = {self.MALICIOUS_DATA, self.MALICIOUS_FILE}
        self.safe_states = {self.SAFE_HTTP, self.SAFE_HTTPS}
        
        # Transition table: δ(state, character) → next_state
        self.delta = {
            # From START state
            (self.Q0_START, 'h'): self.Q1_H,
            (self.Q0_START, 'd'): self.Q6_D,
            (self.Q0_START, 'f'): self.Q10_F,
            
            # HTTP path: h → t → t → p
            (self.Q1_H, 't'): self.Q2_HT,
            (self.Q2_HT, 't'): self.Q3_HTT,
            (self.Q3_HTT, 'p'): self.Q4_HTTP,
            (self.Q4_HTTP, 's'): self.Q5_HTTPS,
            (self.Q4_HTTP, ':'): self.SAFE_HTTP,
            (self.Q5_HTTPS, ':'): self.SAFE_HTTPS,
            
            # DATA path: d → a → t → a
            (self.Q6_D, 'a'): self.Q7_DA,
            (self.Q7_DA, 't'): self.Q8_DAT,
            (self.Q8_DAT, 'a'): self.Q9_DATA,
            (self.Q9_DATA, ':'): self.MALICIOUS_DATA,
            
            # FILE path: f → i → l → e
            (self.Q10_F, 'i'): self.Q11_FI,
            (self.Q11_FI, 'l'): self.Q12_FIL,
            (self.Q12_FIL, 'e'): self.Q13_FILE,
            (self.Q13_FILE, ':'): self.MALICIOUS_FILE,
        }
    
    def check(self, schema: str) -> Dict:
        """Execute DFA with pure state transitions (no string lookups)"""
        if not schema:
            return {
                "triggered": False,
                "state": self.REJECT,
                "reason": "URL missing protocol/schema",
                "value": None,
                "risk_score": 0.0
            }
        
        current_state = self.initial_state
        input_string = schema.lower()
        detected_schema = ""
        
        if self.debug:
            print(f"\n=== SchemaDFA Transition Trace ===")
            print(f"Input: '{schema}'")
        
        # Process each character using transition table
        for char in input_string:
            prev_state = current_state
            current_state = self.delta.get((current_state, char), self.REJECT)
            detected_schema += char
            
            # Visualization for professor
            if self.debug:
                print(f"State {prev_state} --({char})--> State {current_state}")
            
            if current_state == self.REJECT:
                break
        
        # Check for colon to finalize schema
        if current_state not in {self.REJECT, self.SAFE_HTTP, self.SAFE_HTTPS, 
                                  self.MALICIOUS_DATA, self.MALICIOUS_FILE}:
            # Try to transition with ':'
            prev_state = current_state
            current_state = self.delta.get((current_state, ':'), self.REJECT)
            if self.debug:
                print(f"State {prev_state} --(:)--> State {current_state}")
        
        # Determine result based on final state (pure DFA logic)
        if current_state in self.accepting_states:
            triggered = True
            risk_score = self.risk_score
            reason = f"Malicious schema detected via state path: {detected_schema}"
        elif current_state in self.safe_states:
            triggered = False
            risk_score = 0.0
            reason = f"Safe schema detected via state path: {detected_schema}"
        else:
            triggered = False
            risk_score = 0.0
            reason = f"Unknown/Invalid schema - rejected at state {current_state}"
        
        if self.debug:
            print(f"Final State: {current_state} | Triggered: {triggered}")
            print("="*40)
        
        return {
            "triggered": triggered,
            "state": current_state,
            "reason": reason,
            "value": schema,
            "risk_score": risk_score
        }


class TLDDFA:
    """Table-Driven DFA for high-risk TLD detection using pure state transitions"""
    
    def __init__(self, debug=False):
        self.risk_score = 1.0
        self.debug = debug
        
        # Define states for each TLD character path
        self.Q0_START = "Q0_START"
        
        # States for ".zip" path
        self.Q1_Z = "Q1_Z"
        self.Q2_ZI = "Q2_ZI"
        self.Q3_ZIP = "Q3_ZIP"
        
        # States for ".exe" path
        self.Q4_E = "Q4_E"
        self.Q5_EX = "Q5_EX"
        self.Q6_EXE = "Q6_EXE"
        
        # States for ".mov" path
        self.Q7_M = "Q7_M"
        self.Q8_MO = "Q8_MO"
        self.Q9_MOV = "Q9_MOV"
        
        # States for ".tk" path
        self.Q10_T = "Q10_T"
        self.Q11_TK = "Q11_TK"
        
        # States for ".xyz" path
        self.Q12_X = "Q12_X"
        self.Q13_XY = "Q13_XY"
        self.Q14_XYZ = "Q14_XYZ"
        
        # Final states
        self.MALICIOUS = "MALICIOUS"
        self.SAFE = "SAFE"
        self.REJECT = "REJECT"
        
        self.initial_state = self.Q0_START
        self.accepting_states = {self.MALICIOUS}
        
        # Transition table: δ(state, character) → next_state
        self.delta = {
            # From START - branch based on first character
            (self.Q0_START, 'z'): self.Q1_Z,
            (self.Q0_START, 'e'): self.Q4_E,
            (self.Q0_START, 'm'): self.Q7_M,
            (self.Q0_START, 't'): self.Q10_T,
            (self.Q0_START, 'x'): self.Q12_X,
            
            # ZIP path: z → i → p → END
            (self.Q1_Z, 'i'): self.Q2_ZI,
            (self.Q2_ZI, 'p'): self.Q3_ZIP,
            (self.Q3_ZIP, 'END'): self.MALICIOUS,
            
            # EXE path: e → x → e → END
            (self.Q4_E, 'x'): self.Q5_EX,
            (self.Q5_EX, 'e'): self.Q6_EXE,
            (self.Q6_EXE, 'END'): self.MALICIOUS,
            
            # MOV path: m → o → v → END
            (self.Q7_M, 'o'): self.Q8_MO,
            (self.Q8_MO, 'v'): self.Q9_MOV,
            (self.Q9_MOV, 'END'): self.MALICIOUS,
            
            # TK path: t → k → END
            (self.Q10_T, 'k'): self.Q11_TK,
            (self.Q11_TK, 'END'): self.MALICIOUS,
            
            # XYZ path: x → y → z → END
            (self.Q12_X, 'y'): self.Q13_XY,
            (self.Q13_XY, 'z'): self.Q14_XYZ,
            (self.Q14_XYZ, 'END'): self.MALICIOUS,
        }
    
    def check(self, tld: str) -> Dict:
        """Execute DFA with pure state transitions (no string lookups)"""
        if not tld:
            return {
                "triggered": False,
                "state": self.REJECT,
                "reason": "No TLD provided",
                "value": None,
                "risk_score": 0.0
            }
        
        current_state = self.initial_state
        tld_clean = tld.lower().lstrip('.')
        detected_tld = ""
        
        if self.debug:
            print(f"\n=== TLDDFA Transition Trace ===")
            print(f"Input: '.{tld_clean}'")
        
        # Process each character using transition table
        for char in tld_clean:
            prev_state = current_state
            current_state = self.delta.get((current_state, char), self.REJECT)
            detected_tld += char
            
            # Visualization for professor
            if self.debug:
                print(f"State {prev_state} --({char})--> State {current_state}")
            
            if current_state == self.REJECT:
                break
        
        # Check for END marker (string exhausted)
        if current_state != self.REJECT:
            prev_state = current_state
            current_state = self.delta.get((current_state, 'END'), self.SAFE)
            if self.debug:
                print(f"State {prev_state} --(END)--> State {current_state}")
        
        # Determine result based on final state (pure DFA logic)
        if current_state in self.accepting_states:
            triggered = True
            risk_score = self.risk_score
            reason = f"High-risk TLD detected via state path: .{detected_tld}"
        elif current_state == self.SAFE:
            triggered = False
            risk_score = 0.0
            reason = f"Safe TLD detected via state path: .{detected_tld}"
        else:
            triggered = False
            risk_score = 0.0
            reason = f"Unknown TLD - rejected at state {current_state}: .{detected_tld}"
        
        if self.debug:
            print(f"Final State: {current_state} | Triggered: {triggered}")
            print("="*40)
        
        return {
            "triggered": triggered,
            "state": current_state,
            "reason": reason,
            "value": tld_clean,
            "risk_score": risk_score
        }


class Layer1:
    """Layer 1 coordinator: combines Length, Schema, and TLD DFA checks"""
    
    def __init__(self, length_threshold: int = 75, debug: bool = False):
        self.length_dfa = LengthDFA(length_threshold)
        self.schema_dfa = SchemaDFA(debug=debug)
        self.tld_dfa = TLDDFA(debug=debug)
        self.tokenizer = TokenizerDFA()
        self.debug = debug
    
    def analyze(self, url: str) -> Dict:
        """Execute all Layer 1 DFA checks and aggregate results"""
        tokens = self.tokenizer.tokenize(url)
        hostname_components = self.tokenizer.get_hostname_components(tokens["hostname"])
        
        length_check = self.length_dfa.check(url)
        schema_check = self.schema_dfa.check(tokens["schema"])
        tld_check = self.tld_dfa.check(hostname_components["tld"])
        
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
