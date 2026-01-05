"""Layer 2: Advanced DFA checks (Homographs, Subdomains, Punycode)"""

from typing import Dict, List, Set
from .tokenizer import TokenizerDFA


class HomographDFA:
    """DFA for IDN homograph detection (non-ASCII characters)
    
    Formal Definition: M = (Q, Σ, δ, q₀, F)
    Q = {START, SCANNING, FOUND_NON_ASCII, REJECT}
    Σ = {ascii, non_ascii, dot}
    q₀ = START
    F = {FOUND_NON_ASCII}
    """
    
    START = "START"
    SCANNING = "SCANNING"
    FOUND_NON_ASCII = "FOUND_NON_ASCII"
    REJECT = "REJECT"
    
    def __init__(self):
        # Transition table δ: Q × Σ → Q
        self._transition_table = {
            (self.START, "ascii"): self.SCANNING,
            (self.START, "non_ascii"): self.FOUND_NON_ASCII,
            (self.START, "dot"): self.SCANNING,
            (self.SCANNING, "ascii"): self.SCANNING,
            (self.SCANNING, "non_ascii"): self.FOUND_NON_ASCII,
            (self.SCANNING, "dot"): self.SCANNING,
            (self.FOUND_NON_ASCII, "ascii"): self.FOUND_NON_ASCII,
            (self.FOUND_NON_ASCII, "non_ascii"): self.FOUND_NON_ASCII,
            (self.FOUND_NON_ASCII, "dot"): self.FOUND_NON_ASCII,
        }
        self._accepting_states = {self.FOUND_NON_ASCII}
    
    def _classify_char(self, char: str) -> str:
        """Map input character to alphabet symbol"""
        if char == ".":
            return "dot"
        elif ord(char) > 127:
            return "non_ascii"
        else:
            return "ascii"
    
    def _transition(self, state: str, symbol: str) -> str:
        """Transition function δ(q, σ) → q'"""
        return self._transition_table.get((state, symbol), self.REJECT)
    
    def check(self, hostname: str) -> Dict:
        """Execute DFA using table-driven approach"""
        if not hostname:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "details": None
            }
        
        # Standard DFA execution loop
        current_state = self.START
        found_chars = []
        
        for char in hostname:
            symbol = self._classify_char(char)
            current_state = self._transition(current_state, symbol)
            
            # Track non-ASCII characters for reporting (not part of transition logic)
            if symbol == "non_ascii" and char not in found_chars:
                found_chars.append(char)
        
        # Check if final state is accepting
        triggered = current_state in self._accepting_states
        
        return {
            "triggered": triggered,
            "state": current_state,
            "risk_score": 1.5 if triggered else 0.0,
            "reason": "Non-ASCII characters detected in hostname (IDN homograph attack)" if triggered else "No homograph detected",
            "details": {
                "hostname": hostname,
                "non_ascii_chars": found_chars,
                "char_count": len(found_chars)
            } if triggered else None
        }


class DepthDFA:
    """DFA for subdomain depth analysis (counts dots to determine nesting level)
    
    Formal Definition: M = (Q, Σ, δ, q₀, F)
    Q = {START, DEPTH_0, DEPTH_1, DEPTH_2, DEPTH_3, DEPTH_4, DEPTH_EXCESSIVE, REJECT}
    Σ = {dot, other}
    q₀ = START
    F = {DEPTH_EXCESSIVE}
    
    Example: "sub1.sub2.sub3.example.com" has 4 dots
    - Normal domain (domain.tld) = 1 dot
    - 1 subdomain level = 2 dots
    - Excessive if > 6 dots (more than 4 subdomain levels)
    """
    
    START = "START"
    DEPTH_0 = "DEPTH_0"
    DEPTH_1 = "DEPTH_1"
    DEPTH_2 = "DEPTH_2"
    DEPTH_3 = "DEPTH_3"
    DEPTH_4 = "DEPTH_4"
    DEPTH_5 = "DEPTH_5"
    DEPTH_6 = "DEPTH_6"
    DEPTH_EXCESSIVE = "DEPTH_EXCESSIVE"
    REJECT = "REJECT"
    
    def __init__(self, max_depth: int = 4):
        """Initialize DFA with maximum allowed subdomain depth (default: 4 levels = 6 dots total)"""
        self.max_depth = max_depth
        self.max_dots = max_depth + 2  # domain.tld = 1 dot, so 4 subdomains = 6 dots
        
        # Transition table δ: Q × Σ → Q
        self._transition_table = {
            (self.START, "dot"): self.DEPTH_1,
            (self.START, "other"): self.DEPTH_0,
            (self.DEPTH_0, "dot"): self.DEPTH_1,
            (self.DEPTH_0, "other"): self.DEPTH_0,
            (self.DEPTH_1, "dot"): self.DEPTH_2,
            (self.DEPTH_1, "other"): self.DEPTH_1,
            (self.DEPTH_2, "dot"): self.DEPTH_3,
            (self.DEPTH_2, "other"): self.DEPTH_2,
            (self.DEPTH_3, "dot"): self.DEPTH_4,
            (self.DEPTH_3, "other"): self.DEPTH_3,
            (self.DEPTH_4, "dot"): self.DEPTH_5,
            (self.DEPTH_4, "other"): self.DEPTH_4,
            (self.DEPTH_5, "dot"): self.DEPTH_6,
            (self.DEPTH_5, "other"): self.DEPTH_5,
            (self.DEPTH_6, "dot"): self.DEPTH_EXCESSIVE,
            (self.DEPTH_6, "other"): self.DEPTH_6,
            (self.DEPTH_EXCESSIVE, "dot"): self.DEPTH_EXCESSIVE,
            (self.DEPTH_EXCESSIVE, "other"): self.DEPTH_EXCESSIVE,
        }
        self._accepting_states = {self.DEPTH_EXCESSIVE}
    
    def _classify_char(self, char: str) -> str:
        """Map input character to alphabet symbol"""
        return "dot" if char == "." else "other"
    
    def _transition(self, state: str, symbol: str) -> str:
        """Transition function δ(q, σ) → q'"""
        return self._transition_table.get((state, symbol), self.REJECT)
    
    def _get_dot_count(self, state: str) -> int:
        """Extract dot count from state name"""
        if state == self.START or state == self.DEPTH_0:
            return 0
        elif state == self.DEPTH_1:
            return 1
        elif state == self.DEPTH_2:
            return 2
        elif state == self.DEPTH_3:
            return 3
        elif state == self.DEPTH_4:
            return 4
        elif state == self.DEPTH_5:
            return 5
        elif state == self.DEPTH_6:
            return 6
        elif state == self.DEPTH_EXCESSIVE:
            return 7  # More than 6
        return 0
    
    def check(self, hostname: str) -> Dict:
        """Execute DFA using table-driven approach"""
        if not hostname:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "details": None
            }
        
        # Standard DFA execution loop
        current_state = self.START
        
        for char in hostname:
            symbol = self._classify_char(char)
            current_state = self._transition(current_state, symbol)
        
        # Check if final state is accepting
        triggered = current_state in self._accepting_states
        dot_count = self._get_dot_count(current_state)
        subdomain_levels = max(0, dot_count - 1)  # Subtract 1 for domain.tld
        
        return {
            "triggered": triggered,
            "state": current_state,
            "risk_score": 1.0 if triggered else 0.0,
            "reason": f"Excessive subdomain depth: {subdomain_levels} levels (max {self.max_depth})" if triggered else "Subdomain depth within acceptable limits",
            "details": {
                "hostname": hostname,
                "dot_count": dot_count,
                "subdomain_levels": subdomain_levels,
                "max_allowed": self.max_depth
            } if triggered else {
                "hostname": hostname,
                "dot_count": dot_count,
                "subdomain_levels": subdomain_levels
            }
        }


class KeywordDFA:
    """DFA for detecting suspicious keywords using multi-pattern matching
    
    Formal Definition: M = (Q, Σ, δ, q₀, F)
    This DFA implements a simplified Aho-Corasick style automaton to detect
    suspicious keywords like "login", "secure", "admin", etc.
    
    Q = State set (generated dynamically based on keywords)
    Σ = {a-z, 0-9, -, .}
    q₀ = START
    F = {FOUND_<keyword>} for each keyword
    """
    
    START = "START"
    SCANNING = "SCANNING"
    REJECT = "REJECT"
    
    def __init__(self):
        """Initialize DFA with suspicious keywords"""
        self.keywords = [
            "login", "secure", "verify", "update", "account",
            "support", "admin", "panel", "auth", "confirm"
        ]
        
        # Build transition table for all keywords
        self._transition_table = {}
        self._accepting_states = set()
        self._build_keyword_transitions()
    
    def _build_keyword_transitions(self):
        """Build transition table for detecting all keywords (simplified multi-pattern DFA)"""
        # For each keyword, create a linear path of states
        for keyword in self.keywords:
            keyword_lower = keyword.lower()
            
            # Create states for this keyword: START -> L -> LO -> LOG -> LOGI -> LOGIN
            current_prefix = ""
            for i, char in enumerate(keyword_lower):
                current_prefix += char
                state_name = f"MATCH_{current_prefix.upper()}"
                
                # From START or SCANNING, first char transitions to first state
                if i == 0:
                    self._transition_table[(self.START, char)] = state_name
                    self._transition_table[(self.SCANNING, char)] = state_name
                else:
                    prev_prefix = current_prefix[:-1]
                    prev_state = f"MATCH_{prev_prefix.upper()}"
                    self._transition_table[(prev_state, char)] = state_name
                
                # If this is the final character, mark as accepting state
                if i == len(keyword_lower) - 1:
                    self._accepting_states.add(state_name)
                    # After match, transition to SCANNING state for non-keyword chars
                    for c in "abcdefghijklmnopqrstuvwxyz0123456789-.":
                        if c not in keyword_lower:
                            self._transition_table[(state_name, c)] = self.SCANNING
        
        # Default transitions: non-matching chars go to SCANNING
        self._transition_table[(self.START, "other")] = self.SCANNING
        self._transition_table[(self.SCANNING, "other")] = self.SCANNING
    
    def _classify_char(self, char: str) -> str:
        """Map input character to alphabet symbol"""
        char_lower = char.lower()
        if char_lower in "abcdefghijklmnopqrstuvwxyz0123456789-.":
            return char_lower
        return "other"
    
    def _transition(self, state: str, symbol: str) -> str:
        """Transition function δ(q, σ) → q'"""
        # Check direct transition
        if (state, symbol) in self._transition_table:
            return self._transition_table[(state, symbol)]
        
        # If no transition found and we're in a MATCH_ state, reset to SCANNING
        if state.startswith("MATCH_"):
            # Try to continue from SCANNING state
            if (self.SCANNING, symbol) in self._transition_table:
                return self._transition_table[(self.SCANNING, symbol)]
            return self.SCANNING
        
        # Default: stay in SCANNING or go to SCANNING
        return self.SCANNING
    
    def check(self, hostname: str) -> Dict:
        """Execute DFA using table-driven approach"""
        if not hostname:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "details": None
            }
        
        hostname_lower = hostname.lower()
        
        # Standard DFA execution loop
        current_state = self.START
        matched_keywords = []
        
        for char in hostname_lower:
            symbol = self._classify_char(char)
            current_state = self._transition(current_state, symbol)
            
            # Track if we hit an accepting state (keyword found)
            if current_state in self._accepting_states:
                # Extract keyword from state name (e.g., "MATCH_LOGIN" -> "login")
                keyword = current_state.replace("MATCH_", "").lower()
                if keyword not in matched_keywords:
                    matched_keywords.append(keyword)
        
        # Check if any keywords were found
        triggered = len(matched_keywords) > 0
        
        return {
            "triggered": triggered,
            "state": current_state,
            "risk_score": 1.2 if triggered else 0.0,
            "reason": f"Suspicious keyword(s) detected: {', '.join(matched_keywords)}" if triggered else "No suspicious keywords detected",
            "details": {
                "hostname": hostname,
                "keywords_found": matched_keywords,
                "keyword_count": len(matched_keywords)
            } if triggered else None
        }


class PunycodeDFA:
    """DFA for Punycode (xn--) prefix detection
    
    Formal Definition: M = (Q, Σ, δ, q₀, F)
    Q = {START, SCANNING, FOUND_X, FOUND_XN, FOUND_XN_HYPHEN, IN_PUNYCODE, REJECT}
    Σ = {x, n, hyphen, dot, other}
    q₀ = START
    F = {IN_PUNYCODE}
    
    Detects the "xn--" prefix that indicates Punycode encoding
    Example: "xn--e1afmkfd.xn--p1ai" (Russian domain in Punycode)
    """
    
    START = "START"
    SCANNING = "SCANNING"
    FOUND_X = "FOUND_X"
    FOUND_XN = "FOUND_XN"
    FOUND_XN_HYPHEN = "FOUND_XN_HYPHEN"
    IN_PUNYCODE = "IN_PUNYCODE"
    REJECT = "REJECT"
    
    def __init__(self):
        # Transition table δ: Q × Σ → Q
        # This table defines the sequence: x -> n -> - -> - to detect "xn--"
        self._transition_table = {
            # From START: look for 'x' or scan
            (self.START, "x"): self.FOUND_X,
            (self.START, "n"): self.SCANNING,
            (self.START, "hyphen"): self.SCANNING,
            (self.START, "dot"): self.START,  # Reset on dot (new label)
            (self.START, "other"): self.SCANNING,
            
            # From FOUND_X: look for 'n'
            (self.FOUND_X, "x"): self.FOUND_X,  # Stay if another 'x'
            (self.FOUND_X, "n"): self.FOUND_XN,  # Progress to FOUND_XN
            (self.FOUND_X, "hyphen"): self.SCANNING,
            (self.FOUND_X, "dot"): self.START,  # Reset on dot
            (self.FOUND_X, "other"): self.SCANNING,
            
            # From FOUND_XN: look for first hyphen
            (self.FOUND_XN, "x"): self.FOUND_X,
            (self.FOUND_XN, "n"): self.SCANNING,
            (self.FOUND_XN, "hyphen"): self.FOUND_XN_HYPHEN,  # First hyphen
            (self.FOUND_XN, "dot"): self.START,
            (self.FOUND_XN, "other"): self.SCANNING,
            
            # From FOUND_XN_HYPHEN: look for second hyphen to complete "xn--"
            (self.FOUND_XN_HYPHEN, "x"): self.FOUND_X,
            (self.FOUND_XN_HYPHEN, "n"): self.SCANNING,
            (self.FOUND_XN_HYPHEN, "hyphen"): self.IN_PUNYCODE,  # Second hyphen -> ACCEPT
            (self.FOUND_XN_HYPHEN, "dot"): self.START,
            (self.FOUND_XN_HYPHEN, "other"): self.SCANNING,
            
            # From IN_PUNYCODE: stay in accepting state until dot
            (self.IN_PUNYCODE, "x"): self.IN_PUNYCODE,
            (self.IN_PUNYCODE, "n"): self.IN_PUNYCODE,
            (self.IN_PUNYCODE, "hyphen"): self.IN_PUNYCODE,
            (self.IN_PUNYCODE, "dot"): self.START,  # Reset for next label
            (self.IN_PUNYCODE, "other"): self.IN_PUNYCODE,
            
            # From SCANNING: look for 'x' to start detection again
            (self.SCANNING, "x"): self.FOUND_X,
            (self.SCANNING, "n"): self.SCANNING,
            (self.SCANNING, "hyphen"): self.SCANNING,
            (self.SCANNING, "dot"): self.START,
            (self.SCANNING, "other"): self.SCANNING,
        }
        
        self._accepting_states = {self.IN_PUNYCODE}
    
    def _classify_char(self, char: str) -> str:
        """Map input character to alphabet symbol"""
        char_lower = char.lower()
        if char == ".":
            return "dot"
        elif char == "-":
            return "hyphen"
        elif char_lower == "x":
            return "x"
        elif char_lower == "n":
            return "n"
        else:
            return "other"
    
    def _transition(self, state: str, symbol: str) -> str:
        """Transition function δ(q, σ) → q'"""
        return self._transition_table.get((state, symbol), self.REJECT)
    
    def check(self, hostname: str) -> Dict:
        """Execute DFA using strict table-driven approach"""
        if not hostname:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "details": None
            }
        
        hostname_lower = hostname.lower()
        
        # Standard DFA execution loop - ONLY use transition table
        current_state = self.START
        punycode_detected = False
        punycode_parts = []
        current_label = ""
        in_punycode_label = False
        
        for char in hostname_lower:
            symbol = self._classify_char(char)
            
            # Track when we enter/exit punycode labels (for reporting only)
            was_in_punycode = current_state == self.IN_PUNYCODE
            
            # Execute transition (pure DFA logic)
            current_state = self._transition(current_state, symbol)
            
            # Track punycode labels for reporting (not part of transition logic)
            if char == ".":
                if in_punycode_label and current_label:
                    punycode_parts.append(current_label)
                current_label = ""
                in_punycode_label = False
            else:
                current_label += char
                if current_state == self.IN_PUNYCODE:
                    in_punycode_label = True
                    if not was_in_punycode:
                        punycode_detected = True
        
        # Handle last label if it's punycode
        if in_punycode_label and current_label:
            punycode_parts.append(current_label)
        
        # Check if we ever reached an accepting state
        triggered = punycode_detected or current_state in self._accepting_states
        
        return {
            "triggered": triggered,
            "state": current_state,
            "risk_score": 1.3 if triggered else 0.0,
            "reason": f"Punycode encoding detected in {len(punycode_parts)} domain part(s) - may indicate homograph attack" if triggered else "No punycode detected",
            "details": {
                "hostname": hostname,
                "punycode_parts": punycode_parts,
                "punycode_count": len(punycode_parts)
            } if triggered else None
        }


class Layer2:
    """Layer 2 coordinator: combines Homograph, Depth, Keyword, and Punycode DFA checks
    
    All checks now use strict table-driven DFA implementations:
    - HomographDFA: Detects non-ASCII characters (IDN homograph attacks)
    - DepthDFA: Counts dots to detect excessive subdomain nesting
    - KeywordDFA: Multi-pattern matching for suspicious keywords
    - PunycodeDFA: Detects "xn--" Punycode prefix
    """
    
    def __init__(self, max_subdomain_depth: int = 4):
        self.homograph_dfa = HomographDFA()
        self.depth_dfa = DepthDFA(max_subdomain_depth)
        self.keyword_dfa = KeywordDFA()
        self.punycode_dfa = PunycodeDFA()
        self.tokenizer = TokenizerDFA()
    
    def analyze(self, url: str) -> Dict:
        """Execute all Layer 2 DFA checks and aggregate results"""
        tokens = self.tokenizer.tokenize(url)
        hostname = tokens.get("hostname", "")
        
        homograph_result = self.homograph_dfa.check(hostname)
        depth_result = self.depth_dfa.check(hostname)
        keyword_result = self.keyword_dfa.check(hostname)
        punycode_result = self.punycode_dfa.check(hostname)
        
        triggered_count = sum([
            1 if homograph_result["triggered"] else 0,
            1 if depth_result["triggered"] else 0,
            1 if keyword_result["triggered"] else 0,
            1 if punycode_result["triggered"] else 0,
        ])
        
        layer_risk_score = (
            homograph_result["risk_score"] +
            depth_result["risk_score"] +
            keyword_result["risk_score"] +
            punycode_result["risk_score"]
        )
        
        return {
            "layer": "Layer 2 (Advanced)",
            "hostname": hostname,
            "checks": {
                "homograph": {
                    "triggered": homograph_result["triggered"],
                    "state": homograph_result["state"],
                    "risk_score": homograph_result["risk_score"],
                    "reason": homograph_result.get("reason", ""),
                    "details": homograph_result["details"]
                },
                "depth": {
                    "triggered": depth_result["triggered"],
                    "state": depth_result["state"],
                    "risk_score": depth_result["risk_score"],
                    "reason": depth_result.get("reason", ""),
                    "details": depth_result["details"]
                },
                "keyword": {
                    "triggered": keyword_result["triggered"],
                    "state": keyword_result["state"],
                    "risk_score": keyword_result["risk_score"],
                    "reason": keyword_result.get("reason", ""),
                    "details": keyword_result["details"]
                },
                "punycode": {
                    "triggered": punycode_result["triggered"],
                    "state": punycode_result["state"],
                    "risk_score": punycode_result["risk_score"],
                    "reason": punycode_result.get("reason", ""),
                    "details": punycode_result["details"]
                }
            },
            "triggered_count": triggered_count,
            "total_checks": 4,
            "layer_risk_score": layer_risk_score
        }
