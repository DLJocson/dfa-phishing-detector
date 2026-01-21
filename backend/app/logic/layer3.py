"""Layer 3: Threat DFA checks (Chained URLs, Dynamic DNS, Redirects)"""

from typing import Dict
from .tokenizer import TokenizerDFA


class ChainedDFA:
    """DFA for chained URL detection (http://, https://, // in path/query)"""
    
    START = "START"
    SCANNING = "SCANNING"
    FOUND_H = "FOUND_H"
    FOUND_T = "FOUND_T"
    FOUND_T2 = "FOUND_T2"
    FOUND_P = "FOUND_P"
    FOUND_S = "FOUND_S"
    FOUND_COLON = "FOUND_COLON"
    FOUND_SLASH1 = "FOUND_SLASH1"
    FOUND_SLASH2 = "FOUND_SLASH2"
    FOUND_PROTOCOL = "FOUND_PROTOCOL"
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    
    def __init__(self):
        self._transition_table = {
            (self.START, "h"): self.FOUND_H,
            (self.START, "t"): self.SCANNING,
            (self.START, "p"): self.SCANNING,
            (self.START, "s"): self.SCANNING,
            (self.START, ":"): self.SCANNING,
            (self.START, "/"): self.FOUND_SLASH1,
            (self.START, "other"): self.SCANNING,
            (self.SCANNING, "h"): self.FOUND_H,
            (self.SCANNING, "t"): self.SCANNING,
            (self.SCANNING, "p"): self.SCANNING,
            (self.SCANNING, "s"): self.SCANNING,
            (self.SCANNING, ":"): self.SCANNING,
            (self.SCANNING, "/"): self.FOUND_SLASH1,
            (self.SCANNING, "other"): self.SCANNING,
            (self.FOUND_H, "h"): self.FOUND_H,
            (self.FOUND_H, "t"): self.FOUND_T,
            (self.FOUND_H, "p"): self.SCANNING,
            (self.FOUND_H, "s"): self.SCANNING,
            (self.FOUND_H, ":"): self.SCANNING,
            (self.FOUND_H, "/"): self.FOUND_SLASH1,
            (self.FOUND_H, "other"): self.SCANNING,
            (self.FOUND_T, "h"): self.FOUND_H,
            (self.FOUND_T, "t"): self.FOUND_T2,
            (self.FOUND_T, "p"): self.SCANNING,
            (self.FOUND_T, "s"): self.SCANNING,
            (self.FOUND_T, ":"): self.SCANNING,
            (self.FOUND_T, "/"): self.FOUND_SLASH1,
            (self.FOUND_T, "other"): self.SCANNING,
            (self.FOUND_T2, "h"): self.FOUND_H,
            (self.FOUND_T2, "t"): self.SCANNING,
            (self.FOUND_T2, "p"): self.FOUND_P,
            (self.FOUND_T2, "s"): self.SCANNING,
            (self.FOUND_T2, ":"): self.SCANNING,
            (self.FOUND_T2, "/"): self.FOUND_SLASH1,
            (self.FOUND_T2, "other"): self.SCANNING,
            (self.FOUND_P, "h"): self.FOUND_H,
            (self.FOUND_P, "t"): self.SCANNING,
            (self.FOUND_P, "p"): self.SCANNING,
            (self.FOUND_P, "s"): self.FOUND_S,
            (self.FOUND_P, ":"): self.FOUND_COLON,
            (self.FOUND_P, "/"): self.FOUND_SLASH1,
            (self.FOUND_P, "other"): self.SCANNING,
            (self.FOUND_S, "h"): self.FOUND_H,
            (self.FOUND_S, "t"): self.SCANNING,
            (self.FOUND_S, "p"): self.SCANNING,
            (self.FOUND_S, "s"): self.SCANNING,
            (self.FOUND_S, ":"): self.FOUND_COLON,
            (self.FOUND_S, "/"): self.FOUND_SLASH1,
            (self.FOUND_S, "other"): self.SCANNING,
            (self.FOUND_COLON, "h"): self.FOUND_H,
            (self.FOUND_COLON, "t"): self.SCANNING,
            (self.FOUND_COLON, "p"): self.SCANNING,
            (self.FOUND_COLON, "s"): self.SCANNING,
            (self.FOUND_COLON, ":"): self.SCANNING,
            (self.FOUND_COLON, "/"): self.FOUND_SLASH1,
            (self.FOUND_COLON, "other"): self.SCANNING,
            (self.FOUND_SLASH1, "h"): self.FOUND_H,
            (self.FOUND_SLASH1, "t"): self.SCANNING,
            (self.FOUND_SLASH1, "p"): self.SCANNING,
            (self.FOUND_SLASH1, "s"): self.SCANNING,
            (self.FOUND_SLASH1, ":"): self.SCANNING,
            (self.FOUND_SLASH1, "/"): self.FOUND_PROTOCOL,
            (self.FOUND_SLASH1, "other"): self.SCANNING,
            (self.FOUND_PROTOCOL, "h"): self.FOUND_PROTOCOL,
            (self.FOUND_PROTOCOL, "t"): self.FOUND_PROTOCOL,
            (self.FOUND_PROTOCOL, "p"): self.FOUND_PROTOCOL,
            (self.FOUND_PROTOCOL, "s"): self.FOUND_PROTOCOL,
            (self.FOUND_PROTOCOL, ":"): self.FOUND_PROTOCOL,
            (self.FOUND_PROTOCOL, "/"): self.FOUND_PROTOCOL,
            (self.FOUND_PROTOCOL, "other"): self.FOUND_PROTOCOL,
        }
        
        self._accepting_states = {self.FOUND_PROTOCOL}
    
    def _classify_char(self, char: str) -> str:
        """Classify character for state transition"""
        char_lower = char.lower()
        if char_lower == "h":
            return "h"
        elif char_lower == "t":
            return "t"
        elif char_lower == "p":
            return "p"
        elif char_lower == "s":
            return "s"
        elif char_lower == ":":
            return ":"
        elif char_lower == "/":
            return "/"
        else:
            return "other"
    
    def _transition(self, state: str, char_type: str) -> str:
        """Transition function δ(q, σ) → q'"""
        key = (state, char_type)
        return self._transition_table.get(key, self.REJECT)
    
    def check(self, query: str, path: str) -> Dict:
        """Execute DFA and return risk assessment"""
        text_to_check = f"{path}?{query}" if query else path
        
        if not text_to_check:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "details": None
            }
        
        state = self.START
        protocol_found = False
        i = 0
        
        while i < len(text_to_check):
            char = text_to_check[i]
            char_type = self._classify_char(char)
            state = self._transition(state, char_type)
            
            if state == self.FOUND_PROTOCOL and not protocol_found:
                protocol_found = True
            i += 1
        
        triggered = state in self._accepting_states or protocol_found
        
        return {
            "triggered": triggered,
            "state": state,
            "risk_score": 2.0 if triggered else 0.0,
            "reason": "Chained URL detected - http://, https://, or // found in query/path parameters" if triggered else "No chained URLs detected",
            "details": {
                "query": query,
                "path": path,
                "pattern_detected": "http://, https://, or // found in query/path",
                "warning": "Chained URL detected - possible redirect attack"
            } if triggered else None
        }


class DynamicDFA:
    """
    Pure DFA for dynamic DNS/suspicious pattern detection.
    Uses ONLY state transitions with NO auxiliary variables (param_count, digit_count, etc).
    
    Features:
    1. Params: States Count0, Count1, Count2, Count3, Count4, Count5, CountExcessive
       - Track & symbols encountered (parameter count)
    2. Digit Sequence: States D0 (none), D1, D2, D3, D4, D5Plus
       - Track consecutive digit sequences (detect 5+ digits in a row)
    """
    
    # States for parameter counting
    COUNT_0 = "COUNT_0"
    COUNT_1 = "COUNT_1"
    COUNT_2 = "COUNT_2"
    COUNT_3 = "COUNT_3"
    COUNT_4 = "COUNT_4"
    COUNT_5 = "COUNT_5"
    COUNT_EXCESSIVE = "COUNT_EXCESSIVE"
    
    # States for consecutive digit detection
    DIGIT_0 = "DIGIT_0"      # No consecutive digits
    DIGIT_1 = "DIGIT_1"      # 1 consecutive digit
    DIGIT_2 = "DIGIT_2"      # 2 consecutive digits
    DIGIT_3 = "DIGIT_3"      # 3 consecutive digits
    DIGIT_4 = "DIGIT_4"      # 4 consecutive digits
    DIGIT_5_PLUS = "DIGIT_5_PLUS"  # 5+ consecutive digits detected
    
    # Terminal states
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    
    def __init__(self, max_params: int = 5):
        """Initialize pure DFA with state-based counting"""
        self.max_params = max_params
        self._build_transition_tables()
    
    def _build_transition_tables(self):
        """
        Build TWO separate DFAs:
        1. _param_transitions: Tracks & count (parameter count)
        2. _digit_transitions: Tracks consecutive digit sequences
        """
        # ===== PARAMETER COUNTING DFA =====
        # States: COUNT_0, COUNT_1, ..., COUNT_5, COUNT_EXCESSIVE
        self._param_transitions = {
            self.COUNT_0: {
                "&": self.COUNT_1,
                "other": self.COUNT_0,
            },
            self.COUNT_1: {
                "&": self.COUNT_2,
                "other": self.COUNT_1,
            },
            self.COUNT_2: {
                "&": self.COUNT_3,
                "other": self.COUNT_2,
            },
            self.COUNT_3: {
                "&": self.COUNT_4,
                "other": self.COUNT_3,
            },
            self.COUNT_4: {
                "&": self.COUNT_5,
                "other": self.COUNT_4,
            },
            self.COUNT_5: {
                "&": self.COUNT_EXCESSIVE,  # Transition to EXCESSIVE on 6th &
                "other": self.COUNT_5,
            },
            self.COUNT_EXCESSIVE: {
                "&": self.COUNT_EXCESSIVE,
                "other": self.COUNT_EXCESSIVE,
            },
        }
        
        # ===== CONSECUTIVE DIGIT DETECTION DFA =====
        # Tracks sequences of consecutive digits
        self._digit_transitions = {
            self.DIGIT_0: {
                "digit": self.DIGIT_1,
                "other": self.DIGIT_0,
            },
            self.DIGIT_1: {
                "digit": self.DIGIT_2,
                "other": self.DIGIT_0,
            },
            self.DIGIT_2: {
                "digit": self.DIGIT_3,
                "other": self.DIGIT_0,
            },
            self.DIGIT_3: {
                "digit": self.DIGIT_4,
                "other": self.DIGIT_0,
            },
            self.DIGIT_4: {
                "digit": self.DIGIT_5_PLUS,
                "other": self.DIGIT_0,
            },
            self.DIGIT_5_PLUS: {
                "digit": self.DIGIT_5_PLUS,  # Stay in 5+ state
                "other": self.DIGIT_0,
            },
        }
    
    def _classify_char_param(self, char: str) -> str:
        """Classify character for parameter counting DFA"""
        if char == "&":
            return "&"
        else:
            return "other"
    
    def _classify_char_digit(self, char: str) -> str:
        """Classify character for digit sequence DFA"""
        if char.isdigit():
            return "digit"
        else:
            return "other"
    
    def _transition_param(self, state: str, char_type: str) -> str:
        """Pure state transition for parameter counting"""
        if state in self._param_transitions:
            return self._param_transitions[state].get(char_type, state)
        return self.REJECT
    
    def _transition_digit(self, state: str, char_type: str) -> str:
        """Pure state transition for digit sequence detection"""
        if state in self._digit_transitions:
            return self._digit_transitions[state].get(char_type, state)
        return self.REJECT
    
    def check(self, hostname: str, query: str) -> Dict:
        """
        Execute TWO independent pure DFAs:
        1. Parameter counter (via & symbols in query)
        2. Digit sequence detector (via consecutive digits in hostname + query)
        """
        if not hostname and not query:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "details": None
            }
        
        # ===== RUN PARAMETER COUNTING DFA =====
        param_state = self.COUNT_0
        if query:
            for char in query:
                char_type = self._classify_char_param(char)
                param_state = self._transition_param(param_state, char_type)
        
        # ===== RUN DIGIT SEQUENCE DETECTION DFA =====
        digit_state = self.DIGIT_0
        text_to_check = (hostname or "") + (query or "")
        if text_to_check:
            for char in text_to_check:
                char_type = self._classify_char_digit(char)
                digit_state = self._transition_digit(digit_state, char_type)
        
        # ===== DETERMINE RISK BASED ON FINAL STATES =====
        issues = []
        triggered = False
        
        # Check parameter count
        if param_state == self.COUNT_EXCESSIVE:
            issues.append(f"Excessive query parameters (>5 ampersands detected)")
            triggered = True
        
        # Check digit sequence
        if digit_state == self.DIGIT_5_PLUS:
            issues.append(f"High concentration of consecutive digits (5+ detected)")
            triggered = True
        
        # Map state to description
        param_count_desc = {
            self.COUNT_0: "0 parameters",
            self.COUNT_1: "1 parameter",
            self.COUNT_2: "2 parameters",
            self.COUNT_3: "3 parameters",
            self.COUNT_4: "4 parameters",
            self.COUNT_5: "5 parameters",
            self.COUNT_EXCESSIVE: "6+ parameters (excessive)",
        }.get(param_state, "unknown")
        
        digit_count_desc = {
            self.DIGIT_0: "none",
            self.DIGIT_1: "1",
            self.DIGIT_2: "2",
            self.DIGIT_3: "3",
            self.DIGIT_4: "4",
            self.DIGIT_5_PLUS: "5+",
        }.get(digit_state, "unknown")
        
        final_state = self.ACCEPT if not triggered else self.REJECT
        
        reason = ""
        if triggered:
            if issues:
                reason = "; ".join(issues)
            else:
                reason = "Dynamic DNS patterns or excessive parameters detected"
        else:
            reason = "No dynamic DNS patterns or excessive parameters detected"
        
        return {
            "triggered": triggered,
            "state": final_state,
            "risk_score": 1.5 if triggered else 0.0,
            "reason": reason,
            "details": {
                "hostname": hostname,
                "query": query,
                "param_state": param_state,
                "param_count_description": param_count_desc,
                "digit_state": digit_state,
                "consecutive_digits_detected": digit_count_desc,
                "issues": "; ".join(issues),
                "warning": "Dynamic DNS pattern or excessive parameters detected"
            } if triggered else {
                "hostname": hostname,
                "query": query,
                "param_state": param_state,
                "param_count_description": param_count_desc,
                "digit_state": digit_state,
                "consecutive_digits_detected": digit_count_desc,
            }
        }


class RedirectDFA:
    """
    Pure DFA for redirect parameter detection using explicit Trie states.
    Detects redirect keywords: url=, redirect=, next=, etc.
    Uses ONLY state transitions with NO string buffering or external variables.
    
    States represent positions in the keyword matching tree:
    - Each keyword is hardcoded as a sequence of states
    - When we see '=' after matching a keyword, we transition to FOUND_REDIRECT_PARAM
    """
    
    START = "START"
    FOUND_REDIRECT_PARAM = "FOUND_REDIRECT_PARAM"
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    
    def __init__(self):
        """Initialize DFA with explicit keyword matching states"""
        self.redirect_keywords = [
            "url", "redirect", "redirecturl", "redirecturi",
            "next", "goto", "link", "target", "destination",
            "return", "returnurl", "returnuri",
            "continue", "continueurl", "forward", "forwardurl",
            "redir", "rurl", "dest", "out", "to"
        ]
        
        self._build_transition_table()
    
    def _build_transition_table(self):
        """
        Build transition table by building a shared trie for all keywords.
        Handles overlapping prefixes correctly (e.g., "redir", "redirect", "redirecturl").
        
        This is a pure table-driven approach where states represent positions in the trie.
        """
        self._transitions = {}
        self._keyword_targets = {}  # Maps state to keyword
        
        # Build a trie with shared prefix paths
        trie = {}
        current_state = self.START
        
        # Insert all keywords into trie
        for keyword in self.redirect_keywords:
            keyword_lower = keyword.lower()
            current_node = trie
            
            # Navigate/build the trie
            for i, char in enumerate(keyword_lower):
                if char not in current_node:
                    current_node[char] = {}
                current_node = current_node[char]
            
            # Mark end of keyword with a special key
            current_node['$END'] = keyword
        
        # Now convert trie to DFA states
        def trie_to_dfa(node, state_prefix):
            """Recursively convert trie node to DFA states"""
            state_id = state_prefix
            
            # Initialize transitions for this state
            if state_id not in self._transitions:
                self._transitions[state_id] = {}
            
            # If this node marks end of a keyword, record it
            if '$END' in node:
                self._keyword_targets[state_id] = node['$END']
            
            # Add transitions for each character
            for char, next_node in node.items():
                if char != '$END':
                    next_state_id = f"{state_prefix}/{char}"
                    self._transitions[state_id][char] = next_state_id
                    # Recursively process next node
                    trie_to_dfa(next_node, next_state_id)
        
        # Build DFA from trie starting at START state
        trie_to_dfa(trie, self.START)
        
        # Add '=' transitions from all keyword end states to FOUND_REDIRECT_PARAM
        for kw_end_state in list(self._keyword_targets.keys()):
            if kw_end_state not in self._transitions:
                self._transitions[kw_end_state] = {}
            self._transitions[kw_end_state]["="] = self.FOUND_REDIRECT_PARAM
        
        # Add fallback transitions for all states
        for state in list(self._transitions.keys()):
            # '&' always resets to START
            if "&" not in self._transitions[state]:
                self._transitions[state]["&"] = self.START
        
        # FOUND_REDIRECT_PARAM transitions
        self._transitions[self.FOUND_REDIRECT_PARAM] = {
            "&": self.START,
        }
    
    def _transition(self, state: str, char: str) -> str:
        """Pure state transition function δ(q, σ) → q'"""
        if state not in self._transitions:
            return self.REJECT
        
        char_lower = char.lower()
        
        # Try exact character match first
        if char_lower in self._transitions[state]:
            return self._transitions[state][char_lower]
        
        # Check for ampersand (parameter boundary)
        if char == "&" and "&" in self._transitions[state]:
            return self._transitions[state]["&"]
        
        # If we're in the middle of matching a keyword but hit an unexpected character,
        # reset to START (unless it's a special transition we already handled)
        # This ensures we don't get stuck in partial match states
        return self.START
    
    def check(self, query: str) -> Dict:
        """
        Execute pure DFA check - only state transitions, NO string buffering.
        Follows: state = transitions[state][char] strictly.
        """
        if not query:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "details": None
            }
        
        state = self.START
        found_redirect_params = []
        in_keyword = False
        last_keyword = None
        
        # Pure DFA loop: ONLY state transitions
        for char in query:
            prev_state = state
            state = self._transition(state, char)
            
            # Check if we just found a redirect parameter
            if state == self.FOUND_REDIRECT_PARAM and prev_state != self.FOUND_REDIRECT_PARAM:
                # Look up which keyword matched
                if prev_state in self._keyword_targets:
                    keyword = self._keyword_targets[prev_state]
                    if keyword not in found_redirect_params:
                        found_redirect_params.append(keyword)
            
            # Reset when hitting ampersand
            if char == "&":
                in_keyword = False
                last_keyword = None
        
        triggered = len(found_redirect_params) > 0
        
        reason = ""
        if triggered:
            params_str = ", ".join(found_redirect_params)
            reason = f"Redirect parameters detected: {params_str} - possible open redirect vulnerability"
        else:
            reason = "No redirect parameters detected"
        
        return {
            "triggered": triggered,
            "state": state,
            "risk_score": 1.8 if triggered else 0.0,
            "reason": reason,
            "details": {
                "query": query,
                "redirect_params": found_redirect_params,
                "param_count": len(found_redirect_params),
                "warning": "Redirect parameter detected - possible open redirect vulnerability"
            } if triggered else None
        }


class EncodedProtocolDFA:
    """
    Pure DFA for detecting percent-encoded embedded protocols.
    Detects patterns like %68%74%74%70 (encoded "http") and %3A%2F%2F (encoded "://").
    Uses explicit HEX parsing with state-based tracking.
    """
    
    START = "START"
    P = "P"
    # http sequence: %68%74%74%70
    H6 = "H6"
    H68 = "H68"
    H68P = "H68P"
    T7 = "T7"
    T74 = "T74"
    T74P = "T74P"
    T27 = "T27"
    T274 = "T274"
    T274P = "T274P"
    P7 = "P7"
    P70 = "P70"
    # :// sequence: %3A%2F%2F
    HTTP = "HTTP"
    HTTPP = "HTTPP"
    C3 = "C3"
    C3A = "C3A"
    C3AP = "C3AP"
    S2 = "S2"
    S2F = "S2F"
    S2FP = "S2FP"
    S22 = "S22"
    S22F = "S22F"
    FOUND = "FOUND"
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    
    def __init__(self):
        self._build_transition_table()
    
    def _build_transition_table(self):
        self._transitions = {
            self.START: {"%": self.P},
            self.P: {"6": self.H6, "3": self.C3, "2": self.S2},
            # http = %68%74%74%70
            self.H6: {"8": self.H68},
            self.H68: {"%": self.H68P},
            self.H68P: {"7": self.T7},
            self.T7: {"4": self.T74},
            self.T74: {"%": self.T74P},
            self.T74P: {"7": self.T27},
            self.T27: {"4": self.T274},
            self.T274: {"%": self.T274P},
            self.T274P: {"7": self.P7},
            self.P7: {"0": self.P70},
            self.P70: {"%": self.HTTPP},
            # After http, scan for :// = %3A%2F%2F
            self.HTTPP: {"3": self.C3},
            self.C3: {"a": self.C3A, "A": self.C3A},
            self.C3A: {"%": self.C3AP},
            self.C3AP: {"2": self.S2},
            self.S2: {"f": self.S2F, "F": self.S2F},
            self.S2F: {"%": self.S2FP},
            self.S2FP: {"2": self.S22},
            self.S22: {"f": self.S22F, "F": self.S22F},
            self.S22F: {},
        }
    
    def _transition(self, state: str, char: str) -> str:
        if state not in self._transitions:
            return self.START
        return self._transitions[state].get(char, self.START)
    
    def check(self, query: str) -> Dict:
        if not query:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "reason": "No query parameters to analyze",
                "details": None
            }
        state = self.START
        for char in query:
            state = self._transition(state, char)
            if state == self.S22F:
                state = self.FOUND
                break
        triggered = state == self.FOUND
        return {
            "triggered": triggered,
            "state": state,
            "risk_score": 2.5 if triggered else 0.0,
            "reason": "Percent-encoded protocol detected in query parameters - possible embedded malicious URL" if triggered else "No encoded protocols detected",
            "details": {
                "query": query,
                "pattern_detected": "Percent-encoded http:// or similar protocol",
                "warning": "Encoded protocol detected - possible URL injection attack"
            } if triggered else None
        }


class FragmentRedirectDFA:
    """Pure DFA for detecting fragment-based redirects (#// or #/http)."""
    START = "START"
    FOUND_HASH = "FOUND_HASH"
    FOUND_SLASH = "FOUND_SLASH"
    FOUND_DOUBLE_SLASH = "FOUND_DOUBLE_SLASH"
    FOUND_H = "FOUND_H"
    FOUND_T = "FOUND_T"
    FOUND_T2 = "FOUND_T2"
    FOUND_P = "FOUND_P"
    FOUND_HTTP = "FOUND_HTTP"
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    
    def __init__(self):
        self._build_transition_table()
    
    def _build_transition_table(self):
        self._transitions = {
            self.START: {"#": self.FOUND_HASH, "other": self.START},
            self.FOUND_HASH: {"/": self.FOUND_SLASH, "h": self.FOUND_H, "other": self.START},
            self.FOUND_SLASH: {"/": self.FOUND_DOUBLE_SLASH, "h": self.FOUND_H, "other": self.START},
            self.FOUND_DOUBLE_SLASH: {"other": self.FOUND_DOUBLE_SLASH},
            self.FOUND_H: {"t": self.FOUND_T, "other": self.START},
            self.FOUND_T: {"t": self.FOUND_T2, "other": self.START},
            self.FOUND_T2: {"p": self.FOUND_P, "other": self.START},
            self.FOUND_P: {":": self.FOUND_HTTP, "other": self.START},
            self.FOUND_HTTP: {"other": self.FOUND_HTTP},
        }
    
    def _transition(self, state: str, char: str) -> str:
        if state not in self._transitions:
            return self.REJECT
        char_lower = char.lower()
        if char_lower in self._transitions[state]:
            return self._transitions[state][char_lower]
        if "other" in self._transitions[state]:
            return self._transitions[state]["other"]
        return self.REJECT
    
    def check(self, fragment: str) -> Dict:
        if not fragment:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "reason": "No fragment to analyze",
                "details": None
            }
        state = self.START
        for char in fragment:
            state = self._transition(state, char)
        triggered = state in [self.FOUND_DOUBLE_SLASH, self.FOUND_HTTP]
        return {
            "triggered": triggered,
            "state": state,
            "risk_score": 1.5 if triggered else 0.0,
            "reason": "Fragment-based redirect detected - possible client-side redirect attack" if triggered else "No fragment redirects detected",
            "details": {
                "fragment": fragment,
                "pattern_detected": "#// or #/http:// detected",
                "warning": "Fragment redirect detected - possible client-side redirect vulnerability"
            } if triggered else None
        }


class ShortenerDFA:
    """Pure DFA for detecting URL shortener domains using trie."""
    START = "START"
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    
    def __init__(self):
        self.shortener_domains = ["bit.ly", "tinyurl.com", "t.co", "is.gd"]
        self._build_trie()
    
    def _build_trie(self):
        self._transitions = {}
        self._accepting_states = set()
        trie = {}
        for domain in self.shortener_domains:
            node = trie
            for char in domain.lower():
                if char not in node:
                    node[char] = {}
                node = node[char]
            node['$END'] = True
        def trie_to_dfa(node, state_prefix):
            if state_prefix not in self._transitions:
                self._transitions[state_prefix] = {}
            if '$END' in node:
                self._accepting_states.add(state_prefix)
            for char, next_node in node.items():
                if char != '$END':
                    next_state = f"{state_prefix}/{char}"
                    self._transitions[state_prefix][char] = next_state
                    trie_to_dfa(next_node, next_state)
        trie_to_dfa(trie, self.START)
    
    def _transition(self, state: str, char: str) -> str:
        if state not in self._transitions:
            return self.REJECT
        return self._transitions[state].get(char.lower(), self.REJECT)
    
    def check(self, hostname: str) -> Dict:
        if not hostname:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "reason": "No hostname to analyze",
                "details": None
            }
        state = self.START
        for char in hostname:
            state = self._transition(state, char)
            if state == self.REJECT:
                break
        triggered = state in self._accepting_states
        return {
            "triggered": triggered,
            "state": state,
            "risk_score": 2.0 if triggered else 0.0,
            "reason": f"URL shortener domain detected: {hostname} - possible link obfuscation" if triggered else "No URL shortener detected",
            "details": {
                "hostname": hostname,
                "shortener_detected": hostname if triggered else None,
                "warning": "URL shortener detected - destination may be obfuscated"
            } if triggered else None
        }


class CredentialPathDFA:
    """Pure DFA for detecting credential-harvesting paths."""
    START = "START"
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    
    def __init__(self):
        self.keywords = ["login", "verify", "update", "auth", "session"]
        self._build_trie()
    
    def _build_trie(self):
        self._transitions = {}
        self._accepting_states = set()
        trie = {}
        for keyword in self.keywords:
            node = trie
            for char in keyword.lower():
                if char not in node:
                    node[char] = {}
                node = node[char]
            node['$END'] = keyword
        def trie_to_dfa(node, state_prefix):
            if state_prefix not in self._transitions:
                self._transitions[state_prefix] = {}
            if '$END' in node:
                self._accepting_states.add(state_prefix)
            for char, next_node in node.items():
                if char != '$END':
                    next_state = f"{state_prefix}/{char}"
                    self._transitions[state_prefix][char] = next_state
                    trie_to_dfa(next_node, next_state)
            self._transitions[state_prefix]["/"] = self.START
        trie_to_dfa(trie, self.START)
    
    def _transition(self, state: str, char: str) -> str:
        if state not in self._transitions:
            return self.REJECT
        char_lower = char.lower()
        if char_lower in self._transitions[state]:
            return self._transitions[state][char_lower]
        if char == "/":
            return self.START
        if not char.isalpha():
            return self.START
        return self.REJECT
    
    def check(self, path: str) -> Dict:
        if not path:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "reason": "No path to analyze",
                "details": None
            }
        state = self.START
        detected_keywords = []
        current_match = ""
        for char in path:
            state = self._transition(state, char)
            if char.isalpha():
                current_match += char.lower()
            elif char == "/":
                if current_match in self.keywords and current_match not in detected_keywords:
                    detected_keywords.append(current_match)
                current_match = ""
        if current_match:
            for keyword in self.keywords:
                if current_match == keyword.lower() and keyword not in detected_keywords:
                    detected_keywords.append(keyword)
        triggered = len(detected_keywords) > 0
        return {
            "triggered": triggered,
            "state": state,
            "risk_score": 1.2 if triggered else 0.0,
            "reason": f"Credential harvesting path detected: {', '.join(detected_keywords)}" if triggered else "No credential harvesting paths detected",
            "details": {
                "path": path,
                "keywords_detected": detected_keywords,
                "warning": "Credential harvesting path detected - possible phishing attempt"
            } if triggered else None
        }


class SuspiciousTLDDFA:
    """Pure DFA for detecting suspicious top-level domains."""
    START = "START"
    DOT = "DOT"
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    
    def __init__(self):
        self.suspicious_tlds = [".xyz", ".tk", ".top", ".ru", ".cn"]
        self._build_trie()
    
    def _build_trie(self):
        self._transitions = {}
        self._accepting_states = set()
        trie = {}
        for tld in self.suspicious_tlds:
            node = trie
            for char in tld.lower():
                if char not in node:
                    node[char] = {}
                node = node[char]
            node['$END'] = tld
        def trie_to_dfa(node, state_prefix):
            if state_prefix not in self._transitions:
                self._transitions[state_prefix] = {}
            if '$END' in node:
                self._accepting_states.add(state_prefix)
            for char, next_node in node.items():
                if char != '$END':
                    next_state = f"{state_prefix}{char}"
                    self._transitions[state_prefix][char] = next_state
                    trie_to_dfa(next_node, next_state)
        trie_to_dfa(trie, self.START)
        for state in list(self._transitions.keys()):
            if "." not in self._transitions[state]:
                self._transitions[state]["."] = self.START + "."
    
    def _transition(self, state: str, char: str) -> str:
        if state not in self._transitions:
            return self.START if char == "." else self.REJECT
        char_lower = char.lower()
        if char_lower in self._transitions[state]:
            return self._transitions[state][char_lower]
        if char == ".":
            return self.START + "."
        return self.START
    
    def check(self, hostname: str) -> Dict:
        if not hostname:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "reason": "No hostname to analyze",
                "details": None
            }
        state = self.START
        detected_tld = None
        for char in hostname:
            state = self._transition(state, char)
        if state in self._accepting_states:
            for tld in self.suspicious_tlds:
                if tld.lower() in state.lower():
                    detected_tld = tld
                    break
        triggered = state in self._accepting_states
        return {
            "triggered": triggered,
            "state": state,
            "risk_score": 1.0 if triggered else 0.0,
            "reason": f"Suspicious TLD detected: {detected_tld}" if triggered else "No suspicious TLD detected",
            "details": {
                "hostname": hostname,
                "tld_detected": detected_tld,
                "warning": "Suspicious TLD detected - commonly associated with malicious domains"
            } if triggered else None
        }


class Layer3:
    """Layer 3 coordinator: combines all DFA threat detection checks"""
    
    def __init__(self):
        self.chained_dfa = ChainedDFA()
        self.dynamic_dfa = DynamicDFA()
        self.redirect_dfa = RedirectDFA()
        self.encoded_protocol_dfa = EncodedProtocolDFA()
        self.fragment_redirect_dfa = FragmentRedirectDFA()
        self.shortener_dfa = ShortenerDFA()
        self.credential_path_dfa = CredentialPathDFA()
        self.suspicious_tld_dfa = SuspiciousTLDDFA()
        self.tokenizer = TokenizerDFA()
    
    def analyze(self, url: str) -> Dict:
        """Execute all Layer 3 DFA checks and aggregate results"""
        tokens = self.tokenizer.tokenize(url)
        
        query = tokens.get("query", "")
        path = tokens.get("path", "")
        hostname = tokens.get("hostname", "")
        fragment = tokens.get("fragment", "")
        
        chained_result = self.chained_dfa.check(query, path)
        dynamic_result = self.dynamic_dfa.check(hostname, query)
        redirect_result = self.redirect_dfa.check(query)
        encoded_protocol_result = self.encoded_protocol_dfa.check(query)
        fragment_redirect_result = self.fragment_redirect_dfa.check(fragment)
        shortener_result = self.shortener_dfa.check(hostname)
        credential_path_result = self.credential_path_dfa.check(path)
        suspicious_tld_result = self.suspicious_tld_dfa.check(hostname)
        
        triggered_count = sum([
            1 if chained_result["triggered"] else 0,
            1 if dynamic_result["triggered"] else 0,
            1 if redirect_result["triggered"] else 0,
            1 if encoded_protocol_result["triggered"] else 0,
            1 if fragment_redirect_result["triggered"] else 0,
            1 if shortener_result["triggered"] else 0,
            1 if credential_path_result["triggered"] else 0,
            1 if suspicious_tld_result["triggered"] else 0,
        ])
        
        layer_risk_score = (
            chained_result["risk_score"] +
            dynamic_result["risk_score"] +
            redirect_result["risk_score"] +
            encoded_protocol_result["risk_score"] +
            fragment_redirect_result["risk_score"] +
            shortener_result["risk_score"] +
            credential_path_result["risk_score"] +
            suspicious_tld_result["risk_score"]
        )
        
        return {
            "layer": "Layer 3 (Threat)",
            "query": query,
            "path": path,
            "hostname": hostname,
            "fragment": fragment,
            "checks": {
                "chained": {
                    "triggered": chained_result["triggered"],
                    "state": chained_result["state"],
                    "risk_score": chained_result["risk_score"],
                    "reason": chained_result.get("reason", ""),
                    "details": chained_result["details"]
                },
                "dynamic": {
                    "triggered": dynamic_result["triggered"],
                    "state": dynamic_result["state"],
                    "risk_score": dynamic_result["risk_score"],
                    "reason": dynamic_result.get("reason", ""),
                    "details": dynamic_result["details"]
                },
                "redirect": {
                    "triggered": redirect_result["triggered"],
                    "state": redirect_result["state"],
                    "risk_score": redirect_result["risk_score"],
                    "reason": redirect_result.get("reason", ""),
                    "details": redirect_result["details"]
                },
                "encoded_protocol": {
                    "triggered": encoded_protocol_result["triggered"],
                    "state": encoded_protocol_result["state"],
                    "risk_score": encoded_protocol_result["risk_score"],
                    "reason": encoded_protocol_result.get("reason", ""),
                    "details": encoded_protocol_result["details"]
                },
                "fragment_redirect": {
                    "triggered": fragment_redirect_result["triggered"],
                    "state": fragment_redirect_result["state"],
                    "risk_score": fragment_redirect_result["risk_score"],
                    "reason": fragment_redirect_result.get("reason", ""),
                    "details": fragment_redirect_result["details"]
                },
                "shortener": {
                    "triggered": shortener_result["triggered"],
                    "state": shortener_result["state"],
                    "risk_score": shortener_result["risk_score"],
                    "reason": shortener_result.get("reason", ""),
                    "details": shortener_result["details"]
                },
                "credential_path": {
                    "triggered": credential_path_result["triggered"],
                    "state": credential_path_result["state"],
                    "risk_score": credential_path_result["risk_score"],
                    "reason": credential_path_result.get("reason", ""),
                    "details": credential_path_result["details"]
                },
                "suspicious_tld": {
                    "triggered": suspicious_tld_result["triggered"],
                    "state": suspicious_tld_result["state"],
                    "risk_score": suspicious_tld_result["risk_score"],
                    "reason": suspicious_tld_result.get("reason", ""),
                    "details": suspicious_tld_result["details"]
                }
            },
            "triggered_count": triggered_count,
            "total_checks": 8,
            "layer_risk_score": layer_risk_score
        }
