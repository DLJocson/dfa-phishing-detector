"""Layer 3: Threat DFA checks (Chained URLs, Dynamic DNS, Redirects)"""

from typing import Dict
from .tokenizer import TokenizerDFA


class ChainedDFA:
    """
    DFA for chained URL detection in query parameter VALUES only.
    
    Language: Detect embedded URLs (http://, https://, //) ONLY after = in query parameters.
    This eliminates false positives from paths and bare parameter names.
    
    Key states:
    - Scanning through path/query normally
    - FOUND_EQUAL: Transition to this state when '=' is encountered (query value starts)
    - FOUND_EQUAL_H through FOUND_EQUAL_PROTOCOL: Protocol matching ONLY from FOUND_EQUAL
    - FOUND_EQUAL_PROTOCOL: Accepting state (embedded protocol found in value)
    """
    #Defines the finite set of staes for the DFA. FOUND_EQUAL_PROTOCOL is the accepting state.
    START = "START"
    SCANNING = "SCANNING"
    FOUND_EQUAL = "FOUND_EQUAL"           # After '=' - now in query parameter VALUE
    FOUND_EQUAL_H = "FOUND_EQUAL_H"       # 'h' after '='
    FOUND_EQUAL_HT = "FOUND_EQUAL_HT"     # 'ht' after '='
    FOUND_EQUAL_HTT = "FOUND_EQUAL_HTT"   # 'htt' after '='
    FOUND_EQUAL_HTTP = "FOUND_EQUAL_HTTP" # 'http' after '='
    FOUND_EQUAL_COLON = "FOUND_EQUAL_COLON"  # 'http:' after '='
    FOUND_EQUAL_SLASH1 = "FOUND_EQUAL_SLASH1"  # 'http:/' after '='
    FOUND_EQUAL_PROTOCOL = "FOUND_EQUAL_PROTOCOL"  # 'http://' or 'https://' after '='
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    
    def __init__(self):
        """
        Build transition table for Chained URL DFA.
        Key change: Protocol detection ONLY allowed after '=' (query parameter value context).
        """
        self._transition_table = {
            # ===== SCANNING STATES (path and parameter names) =====
            # In path/query, but NOT in a parameter value (before '=')
            (self.START, "="): self.FOUND_EQUAL,
            (self.START, "other"): self.SCANNING,
            (self.SCANNING, "="): self.FOUND_EQUAL,  # Reset to parameter value context
            (self.SCANNING, "h"): self.SCANNING,
            (self.SCANNING, "t"): self.SCANNING,
            (self.SCANNING, "p"): self.SCANNING,
            (self.SCANNING, "s"): self.SCANNING,
            (self.SCANNING, ":"): self.SCANNING,
            (self.SCANNING, "/"): self.SCANNING,
            (self.SCANNING, "other"): self.SCANNING,
            
            # ===== FOUND_EQUAL: We are now in a query parameter VALUE =====
            (self.FOUND_EQUAL, "h"): self.FOUND_EQUAL_H,
            (self.FOUND_EQUAL, "other"): self.FOUND_EQUAL,  # Non-match continues in value
            (self.FOUND_EQUAL, "="): self.FOUND_EQUAL,     # Multiple = symbols
            (self.FOUND_EQUAL, "t"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL, "p"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL, "s"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL, ":"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL, "/"): self.FOUND_EQUAL,
            
            # ===== FOUND_EQUAL_H: We have 'h' after '=' =====
            (self.FOUND_EQUAL_H, "t"): self.FOUND_EQUAL_HT,
            (self.FOUND_EQUAL_H, "h"): self.FOUND_EQUAL_H,
            (self.FOUND_EQUAL_H, "other"): self.FOUND_EQUAL,  # Mismatch: reset to general value scanning
            (self.FOUND_EQUAL_H, "="): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_H, "p"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_H, "s"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_H, ":"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_H, "/"): self.FOUND_EQUAL,
            
            # ===== FOUND_EQUAL_HT: We have 'ht' after '=' =====
            (self.FOUND_EQUAL_HT, "t"): self.FOUND_EQUAL_HTT,
            (self.FOUND_EQUAL_HT, "h"): self.FOUND_EQUAL_H,
            (self.FOUND_EQUAL_HT, "other"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_HT, "="): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_HT, "p"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_HT, "s"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_HT, ":"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_HT, "/"): self.FOUND_EQUAL,
            
            # ===== FOUND_EQUAL_HTT: We have 'htt' after '=' =====
            (self.FOUND_EQUAL_HTT, "p"): self.FOUND_EQUAL_HTTP,
            (self.FOUND_EQUAL_HTT, "h"): self.FOUND_EQUAL_H,
            (self.FOUND_EQUAL_HTT, "t"): self.FOUND_EQUAL_HTT,
            (self.FOUND_EQUAL_HTT, "other"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_HTT, "="): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_HTT, "s"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_HTT, ":"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_HTT, "/"): self.FOUND_EQUAL,
            
            # ===== FOUND_EQUAL_HTTP: We have 'http' after '=' =====
            (self.FOUND_EQUAL_HTTP, ":"): self.FOUND_EQUAL_COLON,
            (self.FOUND_EQUAL_HTTP, "s"): self.FOUND_EQUAL_HTTP,  # Can be 'https' variant
            (self.FOUND_EQUAL_HTTP, "h"): self.FOUND_EQUAL_H,
            (self.FOUND_EQUAL_HTTP, "other"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_HTTP, "="): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_HTTP, "t"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_HTTP, "p"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_HTTP, "/"): self.FOUND_EQUAL,
            
            # ===== FOUND_EQUAL_COLON: We have 'http:' after '=' =====
            (self.FOUND_EQUAL_COLON, "/"): self.FOUND_EQUAL_SLASH1,
            (self.FOUND_EQUAL_COLON, "h"): self.FOUND_EQUAL_H,
            (self.FOUND_EQUAL_COLON, "other"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_COLON, "="): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_COLON, "t"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_COLON, "p"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_COLON, "s"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_COLON, ":"): self.FOUND_EQUAL,
            
            # ===== FOUND_EQUAL_SLASH1: We have 'http:/' after '=' =====
            (self.FOUND_EQUAL_SLASH1, "/"): self.FOUND_EQUAL_PROTOCOL,  # Reached 'http://'
            (self.FOUND_EQUAL_SLASH1, "h"): self.FOUND_EQUAL_H,
            (self.FOUND_EQUAL_SLASH1, "other"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_SLASH1, "="): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_SLASH1, "t"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_SLASH1, "p"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_SLASH1, "s"): self.FOUND_EQUAL,
            (self.FOUND_EQUAL_SLASH1, ":"): self.FOUND_EQUAL,
            
            # ===== FOUND_EQUAL_PROTOCOL: Accepting state - found embedded protocol after '=' =====
            # Once we detect 'http://' or 'https://' in a parameter value, accept any following chars
            (self.FOUND_EQUAL_PROTOCOL, "h"): self.FOUND_EQUAL_PROTOCOL,
            (self.FOUND_EQUAL_PROTOCOL, "t"): self.FOUND_EQUAL_PROTOCOL,
            (self.FOUND_EQUAL_PROTOCOL, "p"): self.FOUND_EQUAL_PROTOCOL,
            (self.FOUND_EQUAL_PROTOCOL, "s"): self.FOUND_EQUAL_PROTOCOL,
            (self.FOUND_EQUAL_PROTOCOL, ":"): self.FOUND_EQUAL_PROTOCOL,
            (self.FOUND_EQUAL_PROTOCOL, "/"): self.FOUND_EQUAL_PROTOCOL,
            (self.FOUND_EQUAL_PROTOCOL, "="): self.FOUND_EQUAL_PROTOCOL,
            (self.FOUND_EQUAL_PROTOCOL, "other"): self.FOUND_EQUAL_PROTOCOL,
        }
        
        # Only FOUND_EQUAL_PROTOCOL is accepting (embedded protocol in parameter value)
        self._accepting_states = {self.FOUND_EQUAL_PROTOCOL}
    
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
        """
        Execute ChainedDFA: Detect embedded URLs in query parameter VALUES only (after '=').
        Returns risk assessment based on whether protocol is found post-equals.
        """
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
        
        # Pure DFA execution: feed each character through transition table
        for char in text_to_check:
            char_type = self._classify_char(char)
            state = self._transition(state, char_type)
            
            # Check if we've reached the accepting state
            if state == self.FOUND_EQUAL_PROTOCOL:
                protocol_found = True
        
        # Accept only if we're in FOUND_EQUAL_PROTOCOL state (embedded protocol in parameter value)
        triggered = state in self._accepting_states
        
        return {
            "triggered": triggered,
            "state": state,
            "risk_score": 2.0 if triggered else 0.0,
            "reason": "Embedded URL detected in query parameter value (http://, https://, //) - possible redirect attack" if triggered else "No embedded URLs in parameter values detected",
            "details": {
                "query": query,
                "path": path,
                "pattern_detected": "http://, https://, or // found in query parameter VALUE (after =)",
                "warning": "Embedded URL in parameter value detected - possible redirect attack"
            } if triggered else None
        }


class DynamicDFA:
    """
    Pure DFA for dynamic DNS/suspicious pattern detection.
    Uses ONLY state transitions with NO auxiliary variables (counters, flags, etc).
    
    Two independent DFAs:
    1. Parameter Counter: Counts '&' symbols to detect excessive parameters (5+)
    2. Hostname Digit Detector: Detects 5+ consecutive digits ONLY in hostname portion
       - Resets digit counter after '/' (entering path) or '?' (entering query)
       - Ignores all digits in path and query portions
    """
    
    # ===== PARAMETER COUNTING STATES =====
    COUNT_0 = "COUNT_0"
    COUNT_1 = "COUNT_1"
    COUNT_2 = "COUNT_2"
    COUNT_3 = "COUNT_3"
    COUNT_4 = "COUNT_4"
    COUNT_5 = "COUNT_5"
    COUNT_EXCESSIVE = "COUNT_EXCESSIVE"
    
    # ===== HOSTNAME-SPECIFIC DIGIT DETECTION STATES =====
    # These states only count consecutive digits WITHIN hostname
    HOST_DIGIT_0 = "HOST_DIGIT_0"          # No consecutive digits in hostname
    HOST_DIGIT_1 = "HOST_DIGIT_1"          # 1 consecutive digit in hostname
    HOST_DIGIT_2 = "HOST_DIGIT_2"          # 2 consecutive digits in hostname
    HOST_DIGIT_3 = "HOST_DIGIT_3"          # 3 consecutive digits in hostname
    HOST_DIGIT_4 = "HOST_DIGIT_4"          # 4 consecutive digits in hostname
    HOST_DIGIT_5_PLUS = "HOST_DIGIT_5_PLUS"  # 5+ consecutive digits in hostname (ACCEPT)
    
    # Terminal states
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    
    def __init__(self, max_params: int = 5):
        """Initialize pure DFA with state-based tracking (no counters)"""
        self.max_params = max_params
        self._build_transition_tables()
    
    def _build_transition_tables(self):
        """
        Build TWO independent DFAs:
        1. _param_transitions: Tracks '&' count for parameter count detection
        2. _hostname_digit_transitions: Tracks consecutive digits ONLY in hostname
        """
        # ===== PARAMETER COUNTING DFA =====
        # Counts '&' symbols in query string; resets on '&'
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
                "&": self.COUNT_EXCESSIVE,  # 6th & detected
                "other": self.COUNT_5,
            },
            self.COUNT_EXCESSIVE: {
                "&": self.COUNT_EXCESSIVE,
                "other": self.COUNT_EXCESSIVE,
            },
        }
        
        # ===== HOSTNAME DIGIT DETECTION DFA =====
        # Tracks consecutive digits ONLY in hostname portion
        # Resets when encountering '/' (path starts) or '?' (query starts)
        self._hostname_digit_transitions = {
            self.HOST_DIGIT_0: {
                "digit": self.HOST_DIGIT_1,
                "path_query_boundary": self.HOST_DIGIT_0,  # '/' or '?' in hostname - reset
                "other": self.HOST_DIGIT_0,
            },
            self.HOST_DIGIT_1: {
                "digit": self.HOST_DIGIT_2,
                "path_query_boundary": self.HOST_DIGIT_0,  # Hit boundary; reset
                "other": self.HOST_DIGIT_0,
            },
            self.HOST_DIGIT_2: {
                "digit": self.HOST_DIGIT_3,
                "path_query_boundary": self.HOST_DIGIT_0,
                "other": self.HOST_DIGIT_0,
            },
            self.HOST_DIGIT_3: {
                "digit": self.HOST_DIGIT_4,
                "path_query_boundary": self.HOST_DIGIT_0,
                "other": self.HOST_DIGIT_0,
            },
            self.HOST_DIGIT_4: {
                "digit": self.HOST_DIGIT_5_PLUS,  # Reached 5+ consecutive digits in hostname!
                "path_query_boundary": self.HOST_DIGIT_0,
                "other": self.HOST_DIGIT_0,
            },
            self.HOST_DIGIT_5_PLUS: {
                "digit": self.HOST_DIGIT_5_PLUS,  # Stay in accepting state
                "path_query_boundary": self.HOST_DIGIT_5_PLUS,  # Boundary found but we're already triggered
                "other": self.HOST_DIGIT_5_PLUS,
            },
        }
    
    def _classify_char_param(self, char: str) -> str:
        """Classify character for parameter counting DFA"""
        if char == "&":
            return "&"
        else:
            return "other"
    
    def _classify_char_hostname_digit(self, char: str, in_hostname: bool) -> str:
        """
        Classify character for hostname digit DFA.
        Returns:
        - "digit": if char is a digit AND we're still in hostname
        - "path_query_boundary": if char is '/' or '?' (transition out of hostname)
        - "other": any other character while in hostname
        """
        if not in_hostname:
            # We've already left hostname, ignore all further chars for this DFA
            return "other"
        
        if char.isdigit():
            return "digit"
        elif char in "/?" :
            return "path_query_boundary"
        else:
            return "other"
    
    def _transition_param(self, state: str, char_type: str) -> str:
        """Pure state transition for parameter counting"""
        if state in self._param_transitions:
            return self._param_transitions[state].get(char_type, state)
        return self.REJECT
    
    def _transition_hostname_digit(self, state: str, char_type: str) -> str:
        """Pure state transition for hostname digit detection"""
        if state in self._hostname_digit_transitions:
            return self._hostname_digit_transitions[state].get(char_type, state)
        return self.REJECT
    
    def check(self, hostname: str, query: str) -> Dict:
        """
        Execute TWO independent pure DFAs:
        1. Parameter counter (via '&' symbols in query)
        2. Hostname digit detector (5+ consecutive digits ONLY in hostname, not in query)
        """
        if not hostname and not query:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "details": None
            }
        
        # ===== RUN PARAMETER COUNTING DFA =====
        # Counts '&' in query
        param_state = self.COUNT_0
        if query:
            for char in query:
                char_type = self._classify_char_param(char)
                param_state = self._transition_param(param_state, char_type)
        
        # ===== RUN HOSTNAME DIGIT DETECTION DFA =====
        # Track consecutive digits ONLY in hostname portion
        digit_state = self.HOST_DIGIT_0
        in_hostname = True  # Hostname comes first in URL
        
        if hostname:
            for char in hostname:
                char_type = self._classify_char_hostname_digit(char, in_hostname)
                digit_state = self._transition_hostname_digit(digit_state, char_type)
                
                # If we hit a boundary character, we've left the hostname
                if char in "/?":
                    in_hostname = False
        
        # ===== DETERMINE RISK BASED ON FINAL STATES =====
        issues = []
        triggered = False
        
        # Check parameter count
        if param_state == self.COUNT_EXCESSIVE:
            issues.append("Excessive query parameters (6+ ampersands detected)")
            triggered = True
        
        # Check hostname digit sequence (ONLY if we detected 5+ in hostname)
        if digit_state == self.HOST_DIGIT_5_PLUS:
            issues.append("High concentration of consecutive digits detected in hostname (5+ digits)")
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
            self.HOST_DIGIT_0: "none",
            self.HOST_DIGIT_1: "1",
            self.HOST_DIGIT_2: "2",
            self.HOST_DIGIT_3: "3",
            self.HOST_DIGIT_4: "4",
            self.HOST_DIGIT_5_PLUS: "5+",
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
                "consecutive_digits_in_hostname": digit_count_desc,
                "issues": "; ".join(issues),
                "warning": "Dynamic DNS pattern or excessive parameters detected"
            } if triggered else {
                "hostname": hostname,
                "query": query,
                "param_state": param_state,
                "param_count_description": param_count_desc,
                "digit_state": digit_state,
                "consecutive_digits_in_hostname": digit_count_desc,
            }
        }


class RedirectDFA:
    """
    Pure DFA for redirect parameter detection using explicit Trie states.
    
    Language: Detect redirect keywords ONLY if their value starts with a protocol.
    
    Two-phase detection via pure DFA states:
    Phase 1: Detect redirect keywords (url=, redirect=, etc.)
    Phase 2: Verify the VALUE starts with http://, https://, or //
    
    States:
    - START: Scanning for redirect keywords
    - Trie states for keyword matching (e.g., "u", "ur", "url")
    - FOUND_REDIRECT_PARAM: We found a redirect keyword followed by '='
    - REDIR_VALUE_START: We're now scanning the parameter value (after '=')
    - REDIR_H through REDIR_HTTP: Checking if value starts with protocol
    - REDIR_PROTOCOL_FOUND: Accept only if we detect http:// or https:// in value
    """
    
    START = "START"
    FOUND_REDIRECT_PARAM = "FOUND_REDIRECT_PARAM"  # After '=' of a redirect keyword
    
    # States for checking protocol in redirect value
    REDIR_VALUE_START = "REDIR_VALUE_START"        # Just after '=' (beginning of value)
    REDIR_H = "REDIR_H"                            # 'h' in value
    REDIR_HT = "REDIR_HT"                          # 'ht' in value
    REDIR_HTT = "REDIR_HTT"                        # 'htt' in value
    REDIR_HTTP = "REDIR_HTTP"                      # 'http' in value
    REDIR_HTTP_COLON = "REDIR_HTTP_COLON"          # 'http:' in value
    REDIR_HTTP_SLASH1 = "REDIR_HTTP_SLASH1"        # 'http:/' in value
    REDIR_PROTOCOL_FOUND = "REDIR_PROTOCOL_FOUND"  # 'http://' or 'https://' in value (ACCEPT)
    
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    
    def __init__(self):
        """Initialize DFA with keyword matching and protocol-in-value detection"""
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
        Build transition table with:
        1. Trie for keyword matching (leading to FOUND_REDIRECT_PARAM on '=')
        2. Protocol detection states (from FOUND_REDIRECT_PARAM)
        """
        self._transitions = {}
        self._keyword_targets = {}  # Maps state to keyword
        
        # Build a trie with shared prefix paths for keywords
        trie = {}
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
        
        # Convert trie to DFA states
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
        
        # ===== PHASE 1: Add '=' transitions from keyword ends to REDIR_VALUE_START =====
        # When we complete a keyword match and see '=', transition to value-checking phase
        for kw_end_state in list(self._keyword_targets.keys()):
            if kw_end_state not in self._transitions:
                self._transitions[kw_end_state] = {}
            self._transitions[kw_end_state]["="] = self.FOUND_REDIRECT_PARAM
        
        # ===== PHASE 2: Protocol detection in redirect parameter VALUE =====
        # These states ONLY appear after we've seen "keyword="
        
        # FOUND_REDIRECT_PARAM: Just saw '=' after a redirect keyword
        # Now we check if the value starts with 'h' (beginning of http/https)
        self._transitions[self.FOUND_REDIRECT_PARAM] = {
            "h": self.REDIR_H,
            "&": self.START,            # Another parameter, reset
            "other": self.START,        # Value doesn't start with protocol, reset
        }
        
        # REDIR_H: We see 'h' in the value
        self._transitions[self.REDIR_H] = {
            "t": self.REDIR_HT,
            "h": self.REDIR_H,          # Another 'h', stay
            "&": self.START,            # Hit parameter boundary, reset
            "other": self.START,        # Mismatch, reset
        }
        
        # REDIR_HT: We see 'ht' in the value
        self._transitions[self.REDIR_HT] = {
            "t": self.REDIR_HTT,
            "h": self.REDIR_H,
            "&": self.START,
            "other": self.START,
        }
        
        # REDIR_HTT: We see 'htt' in the value
        self._transitions[self.REDIR_HTT] = {
            "p": self.REDIR_HTTP,
            "h": self.REDIR_H,
            "&": self.START,
            "other": self.START,
        }
        
        # REDIR_HTTP: We see 'http' in the value
        self._transitions[self.REDIR_HTTP] = {
            ":": self.REDIR_HTTP_COLON,
            "s": self.REDIR_HTTP,       # Could be 'https' - accept 's' to stay in http parsing
            "h": self.REDIR_H,
            "&": self.START,
            "other": self.START,
        }
        
        # REDIR_HTTP_COLON: We see 'http:' in the value
        self._transitions[self.REDIR_HTTP_COLON] = {
            "/": self.REDIR_HTTP_SLASH1,
            "h": self.REDIR_H,
            "&": self.START,
            "other": self.START,
        }
        
        # REDIR_HTTP_SLASH1: We see 'http:/' in the value
        self._transitions[self.REDIR_HTTP_SLASH1] = {
            "/": self.REDIR_PROTOCOL_FOUND,  # We have 'http://' in the value - ACCEPT
            "h": self.REDIR_H,
            "&": self.START,
            "other": self.START,
        }
        
        # REDIR_PROTOCOL_FOUND: We confirmed 'http://' or 'https://' in the redirect value
        # This is the ACCEPTING state - once here, stay here
        self._transitions[self.REDIR_PROTOCOL_FOUND] = {
            "h": self.REDIR_PROTOCOL_FOUND,
            "t": self.REDIR_PROTOCOL_FOUND,
            "p": self.REDIR_PROTOCOL_FOUND,
            "s": self.REDIR_PROTOCOL_FOUND,
            ":": self.REDIR_PROTOCOL_FOUND,
            "/": self.REDIR_PROTOCOL_FOUND,
            "&": self.REDIR_PROTOCOL_FOUND,  # Hit parameter boundary but we're triggered
            "other": self.REDIR_PROTOCOL_FOUND,
        }
        
        # ===== Add fallback transitions for all states =====
        for state in list(self._transitions.keys()):
            # '&' resets to START (parameter boundary)
            if "&" not in self._transitions[state]:
                self._transitions[state]["&"] = self.START
    
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
        
        # Default: check for 'other' catch-all
        if "other" in self._transitions[state]:
            return self._transitions[state]["other"]
        
        # If nothing matches, reset to START
        return self.START
    
    def check(self, query: str) -> Dict:
        """
        Execute pure DFA check: Detect redirect parameters ONLY if value contains protocol.
        - Phase 1: Scan for redirect keyword followed by '='
        - Phase 2: Verify the value starts with 'h' (http/https) and reaches 'http://' or 'https://'
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
        last_keyword = None
        
        # Pure DFA loop: ONLY state transitions
        for char in query:
            prev_state = state
            state = self._transition(state, char)
            
            # Check if we reached protocol-found state
            if state == self.REDIR_PROTOCOL_FOUND and prev_state != self.REDIR_PROTOCOL_FOUND:
                # We just transitioned INTO REDIR_PROTOCOL_FOUND
                # Look up which keyword matched (from trie phase)
                if prev_state in self._keyword_targets:
                    keyword = self._keyword_targets[prev_state]
                    if keyword not in found_redirect_params:
                        found_redirect_params.append(keyword)
            
            # Reset tracking when hitting ampersand (outside of REDIR_PROTOCOL_FOUND)
            if char == "&" and state == self.START:
                last_keyword = None
        
        # Accept ONLY if we're in REDIR_PROTOCOL_FOUND state
        # (redirect param with protocol value detected)
        triggered = state == self.REDIR_PROTOCOL_FOUND
        
        reason = ""
        if triggered:
            params_str = ", ".join(found_redirect_params)
            reason = f"Redirect parameters with protocol values detected: {params_str} - open redirect vulnerability"
        else:
            reason = "No redirect parameters with protocol values detected"
        
        return {
            "triggered": triggered,
            "state": state,
            "risk_score": 1.8 if triggered else 0.0,
            "reason": reason,
            "details": {
                "query": query,
                "redirect_params": found_redirect_params,
                "param_count": len(found_redirect_params),
                "warning": "Redirect parameter with protocol value detected - open redirect vulnerability"
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
