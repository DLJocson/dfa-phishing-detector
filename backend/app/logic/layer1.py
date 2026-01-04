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
    """DFA for protocol/schema validation (detects suspicious protocols)"""
    
    def __init__(self):
        self.risk_score = 0.8
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
        
        self.standard_schemas = {"http", "https"}
        self.suspicious_schemas = {
            "file", "data", "javascript", "vbscript",
            "ftp", "telnet", "gopher"
        }
        
        self.transition_table = {
            (self.START, 'alpha'): self.READING_SCHEMA,
            (self.START, 'default'): self.REJECT,
            (self.READING_SCHEMA, 'alpha'): self.READING_SCHEMA,
            (self.READING_SCHEMA, ':'): self.COLON,
            (self.READING_SCHEMA, 'default'): self.REJECT,
            (self.COLON, '/'): self.SLASH1,
            (self.COLON, 'default'): self.VALIDATE,
            (self.SLASH1, '/'): self.SLASH2,
            (self.SLASH1, 'default'): self.REJECT,
            (self.SLASH2, 'alpha'): self.VALIDATE,
            (self.SLASH2, 'default'): self.VALIDATE,
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
        """Transition function δ(q, σ) → q'"""
        char_type = self._get_char_type(char)
        next_state = self.transition_table.get(
            (state, char_type),
            self.transition_table.get((state, 'default'), self.REJECT)
        )
        if char.isalpha() and (state == self.READING_SCHEMA or next_state == self.READING_SCHEMA):
            schema += char.lower()
        return next_state, schema
    
    def check(self, schema: str) -> Dict:
        """Execute DFA and return risk assessment"""
        if not schema:
            return {
                "triggered": True,
                "state": self.REJECT,
                "reason": "URL missing protocol/schema",
                "value": None,
                "risk_score": 0.0
            }
        
        state = self.initial_state
        collected_schema = ""
        input_string = schema.lower() + "://"
        
        i = 0
        while i < len(input_string):
            char = input_string[i]
            state, collected_schema = self._transition(state, char, collected_schema)
            i += 1
            if state in {self.ACCEPT, self.REJECT, self.VALIDATE}:
                break
        
        if state == self.VALIDATE or state == self.SLASH2 or (state == self.START and collected_schema):
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


class TLDDFA:
    """DFA for high-risk TLD detection"""
    
    def __init__(self):
        self.risk_score = 1.0
        self.START = "START"
        self.COLLECTING_TLD = "COLLECTING_TLD"
        self.LOOKUP = "LOOKUP"
        self.ACCEPT = "ACCEPT"
        self.REJECT = "REJECT"
        self.initial_state = self.START
        self.accepting_states = {self.ACCEPT}
        
        self.high_risk_tlds = {
            "zip", "mov", "exe", "bat", "scr", "app", "run",
            "link", "click", "download", "online", "site", "website",
            "tk", "ml", "ga", "cf", "gq", "pw",
            "xyz", "top", "review", "accountant", "bid", "date",
            "faith", "loan", "men", "party", "racing", "science",
            "stream", "trade", "win", "work", "ooo"
        }
        
        self.transition_table = {
            (self.START, 'alpha'): self.COLLECTING_TLD,
            (self.START, '.'): self.COLLECTING_TLD,
            (self.START, 'default'): self.REJECT,
            (self.COLLECTING_TLD, 'alpha'): self.COLLECTING_TLD,
            (self.COLLECTING_TLD, 'digit'): self.COLLECTING_TLD,
            (self.COLLECTING_TLD, 'hyphen'): self.COLLECTING_TLD,
            (self.COLLECTING_TLD, 'end'): self.LOOKUP,
            (self.COLLECTING_TLD, 'default'): self.LOOKUP,
            (self.LOOKUP, 'any'): self.LOOKUP,
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
        """Transition function δ(q, σ) → q'"""
        char_type = self._get_char_type(char, is_last)
        next_state = self.transition_table.get(
            (state, char_type),
            self.transition_table.get((state, 'default'), self.REJECT)
        )
        return next_state
    
    def check(self, tld: str) -> Dict:
        """Execute DFA and return risk assessment"""
        if not tld:
            return {
                "triggered": False,
                "state": self.REJECT,
                "reason": "No TLD provided",
                "value": None,
                "risk_score": 0.0
            }
        
        state = self.initial_state
        tld_lower = tld.lower().lstrip('.')
        
        i = 0
        while i < len(tld_lower):
            char = tld_lower[i]
            is_last = (i == len(tld_lower) - 1)
            state = self._transition(state, char, is_last)
            i += 1
        
        state = self._transition(state, '', is_last=True)
        
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


class Layer1:
    """Layer 1 coordinator: combines Length, Schema, and TLD DFA checks"""
    
    def __init__(self, length_threshold: int = 75):
        self.length_dfa = LengthDFA(length_threshold)
        self.schema_dfa = SchemaDFA()
        self.tld_dfa = TLDDFA()
        self.tokenizer = TokenizerDFA()
    
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
