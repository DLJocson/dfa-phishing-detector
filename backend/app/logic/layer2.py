"""
===========================================
LAYER 2 - ADVANCED DFA (Formal Automata)
===========================================
Advanced pattern detection using specialized automata:

Homograph DFA: Detects IDN homograph attacks
  - Scans hostname for non-ASCII characters (ord > 127)
  - States: START -> SCANNING -> FOUND_NON_ASCII -> ACCEPT/REJECT
  - Common attack: Cyrillic 'а' (U+0430) looks like Latin 'a' (U+0061)
  - Risk Score: 1.5 (highest Layer 2 weight - very effective attack)

Subdomain DFA: Analyzes subdomain patterns for abuse
  - States: START -> PARSING -> CHECKING_DEPTH/BRAND/KEYWORDS -> ACCEPT/REJECT
  - Excessive depth: a.b.c.d.e.com (more than 4 levels suspicious)
  - Brand jacking: 'paypal.com.login-portal.net' (brand in subdomain)
  - Risk Score: 1.2 (moderate - brand jacking less effective than homograph)

Punycode DFA: Detects encoded homograph attacks
  - States: START -> SCANNING_PREFIX -> FOUND_XN -> ACCEPT/REJECT
  - Punycode format: xn-- prefix indicates IDN encoding
  - Example: xn--pple-43d.com decodes to apple.com with special char
  - Risk Score: 1.3 (moderate-high - depends on combined flags)
"""

from typing import Dict
from .tokenizer import TokenizerDFA


# ========================================
# HOMOGRAPH DFA - FORMAL STATE MACHINE
# ========================================

class HomographDFA:
    """
    Deterministic Finite Automaton for IDN Homograph Detection.
    
    Mathematical Definition:
        M = (Q, Σ, δ, q₀, F)
        
        Q = {START, SCANNING, FOUND_NON_ASCII, ACCEPT, REJECT}
        Σ = {ASCII_CHAR, NON_ASCII_CHAR}
        q₀ = START
        F = {ACCEPT} (accepting states)
        
        δ(q, σ) → q' (transition function defined in _transition_table)
    
    Attack Vector:
    - IDN allows non-ASCII characters in domain names
    - Similar-looking characters from different alphabets fool users
    - Cyrillic 'а' (U+0430) vs Latin 'a' (U+0061) appear identical
    - Also exploited: Greek, Coptic, Armenian, Georgian alphabets
    """
    
    # State definitions
    START = "START"
    SCANNING = "SCANNING"
    FOUND_NON_ASCII = "FOUND_NON_ASCII"
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    
    def __init__(self):
        # Transition table: (state, char_type) -> next_state
        self._transition_table = {
            # START state: Begin scanning
            (self.START, "ascii"): self.SCANNING,
            (self.START, "non_ascii"): self.FOUND_NON_ASCII,
            (self.START, "dot"): self.SCANNING,
            
            # SCANNING state: Look for non-ASCII characters
            (self.SCANNING, "ascii"): self.SCANNING,
            (self.SCANNING, "non_ascii"): self.FOUND_NON_ASCII,
            (self.SCANNING, "dot"): self.SCANNING,
            
            # FOUND_NON_ASCII state: Homograph attack detected!
            (self.FOUND_NON_ASCII, "ascii"): self.FOUND_NON_ASCII,
            (self.FOUND_NON_ASCII, "non_ascii"): self.FOUND_NON_ASCII,
            (self.FOUND_NON_ASCII, "dot"): self.FOUND_NON_ASCII,
        }
        
        # Accepting states
        self._accepting_states = {self.FOUND_NON_ASCII}
    
    def _classify_char(self, char: str) -> str:
        """Classify character as ASCII, non-ASCII, or dot"""
        if char == ".":
            return "dot"
        elif ord(char) > 127:
            return "non_ascii"
        else:
            return "ascii"
    
    def _transition(self, state: str, char_type: str) -> str:
        """δ(q, σ) → q' - transition function"""
        key = (state, char_type)
        return self._transition_table.get(key, self.REJECT)
    
    def check(self, hostname: str) -> Dict:
        """
        Scan hostname for non-ASCII characters using formal DFA.
        
        Returns:
            dict with keys: triggered (bool), state (str), risk_score (float), details (dict)
        """
        if not hostname:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "details": None
            }
        
        # Single while loop - formal DFA character processing
        state = self.START
        found_chars = []
        i = 0
        while i < len(hostname):
            char = hostname[i]
            char_type = self._classify_char(char)
            state = self._transition(state, char_type)
            
            # Track found non-ASCII characters
            if char_type == "non_ascii" and char not in found_chars:
                found_chars.append(char)
            
            i += 1
        
        # Check if final state is accepting state
        triggered = state in self._accepting_states
        
        return {
            "triggered": triggered,
            "state": state,
            "risk_score": 1.5 if triggered else 0.0,  # 1.5x weight for homograph attacks
            "details": {
                "hostname": hostname,
                "non_ascii_chars": found_chars,
                "char_count": len(found_chars)
            } if triggered else None
        }


# ========================================
# SUBDOMAIN DFA - FORMAL STATE MACHINE
# ========================================

class SubdomainDFA:
    """
    Deterministic Finite Automaton for Subdomain Pattern Analysis.
    
    Mathematical Definition:
        M = (Q, Σ, δ, q₀, F)
        
        Q = {START, PARSING, DEPTH_CHECK, BRAND_CHECK, KEYWORD_CHECK, ACCEPT, REJECT}
        Σ = {DOT, ALPHA, DIGIT, HYPHEN, OTHER}
        q₀ = START
        F = {DEPTH_CHECK, BRAND_CHECK, KEYWORD_CHECK, ACCEPT} (various accepting states based on issue type)
        
        δ(q, σ) → q' (transition function defined in _transition_table)
    
    Attack Vectors:
    1. Excessive Depth: a.b.c.d.e.f.com
       - Legitimate sites rarely need 4+ subdomain levels
       - Attackers use depth to obscure the real domain
       
    2. Brand Jacking: paypal.com.attacker-site.net
       - Domain starts with trusted brand name
       - User sees 'paypal.com' but actual domain is 'attacker-site.net'
       
    3. Suspicious Keywords: secure.login.verify.example.com
       - Words like 'secure', 'login', 'verify' indicate phishing
    """
    
    # State definitions
    START = "START"
    PARSING = "PARSING"
    DEPTH_CHECK = "DEPTH_CHECK"
    BRAND_CHECK = "BRAND_CHECK"
    KEYWORD_CHECK = "KEYWORD_CHECK"
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    
    def __init__(self, max_depth: int = 4):
        self.max_depth = max_depth
        
        # Transition table: (state, input_type) -> next_state
        self._transition_table = {
            # START state: Begin parsing
            (self.START, "dot"): self.PARSING,
            (self.START, "alpha"): self.PARSING,
            (self.START, "digit"): self.PARSING,
            (self.START, "hyphen"): self.PARSING,
            
            # PARSING state: Count parts and extract subdomains
            (self.PARSING, "dot"): self.PARSING,
            (self.PARSING, "alpha"): self.PARSING,
            (self.PARSING, "digit"): self.PARSING,
            (self.PARSING, "hyphen"): self.PARSING,
        }
        
        # Accepting states (detected issues)
        self._accepting_states = {self.DEPTH_CHECK, self.BRAND_CHECK, self.KEYWORD_CHECK, self.ACCEPT}
        
        # Brand and keyword databases
        self.common_brands = {
            "paypal", "apple", "google", "microsoft", "amazon",
            "facebook", "twitter", "instagram", "linkedin",
            "netflix", "spotify", "ebay", "bankofamerica",
            "chase", "wellsfargo", "citi", "visa", "mastercard",
            "github", "gitlab", "stackoverflow"
        }
        
        self.suspicious_keywords = {
            "secure", "login", "verify", "update", "account",
            "support", "admin", "panel", "auth", "confirm",
            "validate", "authenticate", "authorize"
        }
    
    def _classify_char(self, char: str) -> str:
        """Classify character type"""
        if char == ".":
            return "dot"
        elif char == "-":
            return "hyphen"
        elif char.isalpha():
            return "alpha"
        elif char.isdigit():
            return "digit"
        else:
            return "other"
    
    def _transition(self, state: str, char_type: str) -> str:
        """δ(q, σ) → q' - transition function"""
        key = (state, char_type)
        return self._transition_table.get(key, self.REJECT)
    
    def check(self, hostname: str) -> Dict:
        """
        Analyze subdomain patterns using formal DFA.
        Detects excessive depth, brand jacking, and suspicious keywords.
        
        Returns:
            dict with keys: triggered (bool), state (str), risk_score (float), details (dict)
        """
        if not hostname:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "details": None
            }
        
        # Single while loop - parse hostname into parts
        state = self.START
        parts = []
        current_part = ""
        i = 0
        while i < len(hostname):
            char = hostname[i]
            char_type = self._classify_char(char)
            state = self._transition(state, char_type)
            
            if char == ".":
                if current_part:
                    parts.append(current_part)
                    current_part = ""
            else:
                current_part += char
            
            i += 1
        
        # Add last part
        if current_part:
            parts.append(current_part)
        
        # Analyze subdomain structure
        triggered = False
        issue_type = None
        issue_details = {}
        
        # Check 1: Excessive depth (more than max_depth + 2 parts = more than max_depth subdomains)
        if len(parts) > self.max_depth + 2:
            triggered = True
            issue_type = self.DEPTH_CHECK
            issue_details["excessive_depth"] = True
            issue_details["depth"] = len(parts) - 2
            issue_details["max_allowed"] = self.max_depth
        
        # Check 2: Brand jacking
        if len(parts) >= 3 and not triggered:
            subdomain = '.'.join(parts[:-2]).lower()
            domain = parts[-2].lower()
            
            for brand in self.common_brands:
                if brand in subdomain and brand not in domain:
                    triggered = True
                    issue_type = self.BRAND_CHECK
                    issue_details["brand_jacking"] = True
                    issue_details["brand_in_subdomain"] = brand
                    break
        
        # Check 3: Suspicious keywords
        if len(parts) >= 3 and not triggered:
            subdomain_str = '.'.join(parts[:-2]).lower()
            for keyword in self.suspicious_keywords:
                if keyword in subdomain_str:
                    triggered = True
                    issue_type = self.KEYWORD_CHECK
                    issue_details["suspicious_keyword"] = True
                    issue_details["keyword"] = keyword
                    break
        
        # Determine final state and risk score
        final_state = issue_type if triggered else self.ACCEPT
        risk_score = 1.2 if triggered else 0.0  # 1.2x weight for subdomain abuse
        
        return {
            "triggered": triggered,
            "state": final_state,
            "risk_score": risk_score,
            "details": {
                "hostname": hostname,
                "parts": parts,
                "num_subdomains": len(parts) - 2,
                "issues": issue_details
            } if triggered else {
                "hostname": hostname,
                "parts": parts,
                "num_subdomains": len(parts) - 2
            }
        }


# ========================================
# PUNYCODE DFA - FORMAL STATE MACHINE
# ========================================

class PunycodeDFA:
    """
    Deterministic Finite Automaton for Punycode (xn--) Detection.
    
    Mathematical Definition:
        M = (Q, Σ, δ, q₀, F)
        
        Q = {START, SCANNING, FOUND_X, FOUND_N, FOUND_HYPHEN, FOUND_XN_PREFIX, ACCEPT, REJECT}
        Σ = {'x', 'n', '-', OTHER_CHAR}
        q₀ = START
        F = {FOUND_XN_PREFIX} (accepting state when xn-- prefix detected)
        
        δ(q, σ) → q' (transition function defined in _transition_table)
    
    Attack Vector:
    - Punycode allows IDN domains to be encoded in ASCII (xn-- prefix)
    - Example: xn--pple-43d.com decodes to "ąpple.com" (with special char)
    - Browser shows the punycode version to the user by default
    - Users don't realize they're on a different domain
    - Legitimate uses exist but heavily abused for homograph attacks
    """
    
    # State definitions
    START = "START"
    SCANNING = "SCANNING"
    FOUND_X = "FOUND_X"
    FOUND_N = "FOUND_N"
    FOUND_HYPHEN = "FOUND_HYPHEN"
    FOUND_XN_PREFIX = "FOUND_XN_PREFIX"
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    
    def __init__(self):
        # Transition table: (state, char_type) -> next_state
        # Char types: 'x', 'n', '-', 'other'
        self._transition_table = {
            # START state: Look for 'x'
            (self.START, "x"): self.FOUND_X,
            (self.START, "n"): self.SCANNING,
            (self.START, "-"): self.SCANNING,
            (self.START, "other"): self.SCANNING,
            (self.START, "dot"): self.SCANNING,
            
            # FOUND_X state: Look for 'n'
            (self.FOUND_X, "x"): self.FOUND_X,
            (self.FOUND_X, "n"): self.FOUND_N,
            (self.FOUND_X, "-"): self.SCANNING,
            (self.FOUND_X, "other"): self.SCANNING,
            (self.FOUND_X, "dot"): self.SCANNING,
            
            # FOUND_N state: Look for '-'
            (self.FOUND_N, "x"): self.FOUND_X,
            (self.FOUND_N, "n"): self.SCANNING,
            (self.FOUND_N, "-"): self.FOUND_HYPHEN,
            (self.FOUND_N, "other"): self.SCANNING,
            (self.FOUND_N, "dot"): self.SCANNING,
            
            # FOUND_HYPHEN state: Confirmed xn-- prefix!
            (self.FOUND_HYPHEN, "x"): self.FOUND_XN_PREFIX,
            (self.FOUND_HYPHEN, "n"): self.FOUND_XN_PREFIX,
            (self.FOUND_HYPHEN, "-"): self.FOUND_XN_PREFIX,
            (self.FOUND_HYPHEN, "other"): self.FOUND_XN_PREFIX,
            (self.FOUND_HYPHEN, "dot"): self.SCANNING,
            
            # FOUND_XN_PREFIX state: Punycode encoding detected
            (self.FOUND_XN_PREFIX, "x"): self.FOUND_XN_PREFIX,
            (self.FOUND_XN_PREFIX, "n"): self.FOUND_XN_PREFIX,
            (self.FOUND_XN_PREFIX, "-"): self.FOUND_XN_PREFIX,
            (self.FOUND_XN_PREFIX, "other"): self.FOUND_XN_PREFIX,
            (self.FOUND_XN_PREFIX, "dot"): self.SCANNING,
            
            # SCANNING state: Continue looking for xn-- in next domain part
            (self.SCANNING, "x"): self.FOUND_X,
            (self.SCANNING, "n"): self.SCANNING,
            (self.SCANNING, "-"): self.SCANNING,
            (self.SCANNING, "other"): self.SCANNING,
            (self.SCANNING, "dot"): self.SCANNING,
        }
        
        # Accepting states (found xn-- prefix)
        self._accepting_states = {self.FOUND_XN_PREFIX}
    
    def _classify_char(self, char: str) -> str:
        """Classify character for state transition"""
        if char == ".":
            return "dot"
        elif char == "-":
            return "-"
        elif char.lower() == "x":
            return "x"
        elif char.lower() == "n":
            return "n"
        else:
            return "other"
    
    def _transition(self, state: str, char_type: str) -> str:
        """δ(q, σ) → q' - transition function"""
        key = (state, char_type)
        return self._transition_table.get(key, self.REJECT)
    
    def check(self, hostname: str) -> Dict:
        """
        Scan hostname for Punycode (xn--) encoding using formal DFA.
        
        Returns:
            dict with keys: triggered (bool), state (str), risk_score (float), details (dict)
        """
        if not hostname:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "details": None
            }
        
        hostname_lower = hostname.lower()
        
        # Single while loop - scan each character with state transitions
        state = self.START
        punycode_parts = []
        current_part = ""
        found_punycode_in_part = False
        i = 0
        
        while i < len(hostname_lower):
            char = hostname_lower[i]
            char_type = self._classify_char(char)
            
            # Track domain parts for Punycode detection
            if char == ".":
                # If current part had xn--, record it
                if found_punycode_in_part and current_part:
                    punycode_parts.append(current_part)
                current_part = ""
                found_punycode_in_part = False
                state = self.SCANNING  # Reset state for next part
            else:
                current_part += char
                # Check if we just found the xn-- prefix pattern
                if state == self.START and char == "x":
                    state = self.FOUND_X
                elif state == self.FOUND_X and char == "n":
                    state = self.FOUND_N
                elif state == self.FOUND_N and char == "-":
                    state = self.FOUND_HYPHEN
                    found_punycode_in_part = True
                elif state == self.FOUND_HYPHEN:
                    state = self.FOUND_XN_PREFIX
                elif state in [self.FOUND_XN_PREFIX, self.SCANNING]:
                    # Stay in state or transition
                    state = self._transition(state, char_type)
                else:
                    state = self._transition(state, char_type)
            
            i += 1
        
        # Check last part
        if found_punycode_in_part and current_part:
            punycode_parts.append(current_part)
        
        # Check if final state is accepting state
        triggered = len(punycode_parts) > 0
        
        return {
            "triggered": triggered,
            "state": self.FOUND_XN_PREFIX if triggered else self.ACCEPT,
            "risk_score": 1.3 if triggered else 0.0,  # 1.3x weight for Punycode encoding
            "details": {
                "hostname": hostname,
                "punycode_parts": punycode_parts,
                "punycode_count": len(punycode_parts),
                "warning": "Punycode encoding detected - may indicate homograph attack"
            } if triggered else None
        }


# ========================================
# LAYER 2 COORDINATOR
# ========================================

class Layer2:
    """
    Coordinates all Layer 2 Advanced DFA checks.
    
    Mathematical Approach:
    - Each DFA independently analyzes a specific attack vector
    - Risk scores are weighted per DFA: Homograph (1.5), Subdomain (1.2), Punycode (1.3)
    - Final risk = sum of individual DFA risk scores
    - Range: 0.0 (no threats) to 3.8 (all DFAs triggered)
    
    Integration:
    - Single while loop processing throughout all DFAs
    - No threading or multiprocessing
    - O(n) complexity where n = hostname length
    """
    
    def __init__(self, max_subdomain_depth: int = 4):
        self.homograph_dfa = HomographDFA()
        self.subdomain_dfa = SubdomainDFA(max_subdomain_depth)
        self.punycode_dfa = PunycodeDFA()
        self.tokenizer = TokenizerDFA()
    
    def analyze(self, url: str) -> Dict:
        """
        Execute all Layer 2 DFA checks and aggregate results.
        
        Returns:
            dict with layer info, individual check results, triggered count, and risk score
        """
        tokens = self.tokenizer.tokenize(url)
        hostname = tokens.get("hostname", "")
        
        # Execute each DFA check
        homograph_result = self.homograph_dfa.check(hostname)
        subdomain_result = self.subdomain_dfa.check(hostname)
        punycode_result = self.punycode_dfa.check(hostname)
        
        # Count how many DFAs were triggered
        triggered_count = sum([
            1 if homograph_result["triggered"] else 0,
            1 if subdomain_result["triggered"] else 0,
            1 if punycode_result["triggered"] else 0,
        ])
        
        # Calculate aggregate risk score
        layer_risk_score = (
            homograph_result["risk_score"] +
            subdomain_result["risk_score"] +
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
                    "details": homograph_result["details"]
                },
                "subdomain": {
                    "triggered": subdomain_result["triggered"],
                    "state": subdomain_result["state"],
                    "risk_score": subdomain_result["risk_score"],
                    "details": subdomain_result["details"]
                },
                "punycode": {
                    "triggered": punycode_result["triggered"],
                    "state": punycode_result["state"],
                    "risk_score": punycode_result["risk_score"],
                    "details": punycode_result["details"]
                }
            },
            "triggered_count": triggered_count,
            "total_checks": 3,
            "layer_risk_score": layer_risk_score
        }

