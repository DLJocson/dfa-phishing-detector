from typing import Dict
from .tokenizer import TokenizerDFA


#this is for the DepthDFA 
MULTILABEL_TLDS = {
    "co.uk", "gov.uk", "ac.uk", "org.uk",
    "co.jp", "or.jp", "go.jp",
    "com.au", "gov.au", "edu.au", "org.au",
    "co.nz", "govt.nz",
    "com.br", "gov.br", "org.br",
    "com.mx", "org.mx", "gov.mx",
    "co.in", "gov.in", "org.in",
    "co.kr", "or.kr", "go.kr",
    "gov.ph", "com.ph", "org.ph",
    "co.th", "or.th", "ac.th",
    "co.id", "go.id", "org.id",
}

# ASCII character set
ASCII_CHARS = set(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r"
)

# Map confusable characters to their hex codes (reverse of CONFUSABLE_MAP for lookup)
CONFUSABLE_CHAR_MAP = {
    # Cyrillic
    'а': 0x0430,  # а (Cyrillic a)
    'е': 0x0435,  # е (Cyrillic e)
    'о': 0x043E,  # о (Cyrillic o)
    'п': 0x043F,  # п (Cyrillic p)
    'с': 0x0441,  # с (Cyrillic c)
    'х': 0x0445,  # х (Cyrillic x)
    'у': 0x0443,  # у (Cyrillic y)
    'м': 0x043C,  # м (Cyrillic m)
    'н': 0x043D,  # н (Cyrillic n)
    'р': 0x0440,  # р (Cyrillic r/p)
    # Greek
    'ά': 0x03AC,  # ά (Greek alpha)
    'έ': 0x03AD,  # έ (Greek epsilon)
    'ο': 0x03BF,  # ο (Greek omicron)
    'ν': 0x03BD,  # ν (Greek nu)
    # Latin extended
    'ā': 0x0101,  # ā (a with macron)
    'ē': 0x0113,  # ē (e with macron)
    # Math digit lookalikes
    '𝟬': 0x1D7EC,  # Mathematical bold digit 0
    '𝟭': 0x1D7ED,  # Mathematical bold digit 1
}

#function for DepthDFA
#checks for the multi-label TLDs and counts them as 1
def normalize_hostname_for_depth(hostname: str) -> str:
    hostname_lower = hostname.lower()
    parts = hostname_lower.split('.')
    
    if len(parts) < 2:
        return hostname_lower
    if len(parts) >= 3:
        tld_2label = f"{parts[-2]}.{parts[-1]}"
        if tld_2label in MULTILABEL_TLDS:
            return hostname_lower
        if len(parts) >= 4:
            tld_3label = f"{parts[-3]}.{parts[-2]}.{parts[-1]}"
            if tld_3label in MULTILABEL_TLDS:
                return hostname_lower
    
    return hostname_lower

#this checks for any characters that is pretending to be an ASCII character
class ConfusablesDFA:
    """
    Formal Definition: M = (Q, Σ, δ, q₀, F)
    Q = {START, SCANNING, FOUND_CONFUSABLE, REJECT}
    Σ = {ascii, confusable_nonascii, other_nonascii, dot}
    q₀ = START
    F = {FOUND_CONFUSABLE}
    """
    
    START = "START"
    SCANNING = "SCANNING"
    FOUND_CONFUSABLE = "FOUND_CONFUSABLE"
    REJECT = "REJECT"
    
    def __init__(self):
        self._transition_table = {
            (self.START, "ascii"): self.SCANNING,
            (self.START, "confusable_nonascii"): self.FOUND_CONFUSABLE,
            (self.START, "other_nonascii"): self.SCANNING,
            (self.START, "dot"): self.SCANNING,
            (self.SCANNING, "ascii"): self.SCANNING,
            (self.SCANNING, "confusable_nonascii"): self.FOUND_CONFUSABLE,
            (self.SCANNING, "other_nonascii"): self.SCANNING,
            (self.SCANNING, "dot"): self.SCANNING,
            (self.FOUND_CONFUSABLE, "ascii"): self.FOUND_CONFUSABLE,
            (self.FOUND_CONFUSABLE, "confusable_nonascii"): self.FOUND_CONFUSABLE,
            (self.FOUND_CONFUSABLE, "other_nonascii"): self.FOUND_CONFUSABLE,
            (self.FOUND_CONFUSABLE, "dot"): self.FOUND_CONFUSABLE,
        }
        self._accepting_states = {self.FOUND_CONFUSABLE}
    
    def _classify_char(self, char: str) -> str:
        if char == ".":
            return "dot"
        elif char in ASCII_CHARS:
            return "ascii"
        elif char in CONFUSABLE_CHAR_MAP:
            return "confusable_nonascii"
        else:
            return "other_nonascii"
    
    def _transition(self, state: str, symbol: str) -> str:
        return self._transition_table.get((state, symbol), self.REJECT)
    
    def check(self, hostname: str) -> Dict:
        if not hostname:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "details": None,
                "reason": ""
            }
        
        current_state = self.START
        confusable_chars = []
        
        for char in hostname:
            symbol = self._classify_char(char)
            current_state = self._transition(current_state, symbol)
            if symbol == "confusable_nonascii" and char not in confusable_chars:
                confusable_chars.append(char)
        
        triggered = current_state in self._accepting_states
        risk_score = 1.5 if triggered else 0.0
        
        if triggered:
            reason = f"Confusable lookalike characters detected (homograph risk): {', '.join(confusable_chars)}"
        else:
            reason = "No known homograph lookalikes detected (ASCII or benign non-ASCII only)"
        
        return {
            "triggered": triggered,
            "state": current_state,
            "risk_score": risk_score,
            "reason": reason,
            "details": {
                "hostname": hostname,
                "confusable_chars": confusable_chars,
                "char_count": len(confusable_chars)
            } if triggered else None
        }

#this checks for the depth of the subdomains in a hostname
#
class DepthDFA:
    """
    Formal Definition: M = (Q, Σ, δ, q₀, F)
    Q = {START, DEPTH_0, DEPTH_1, DEPTH_2, DEPTH_3, DEPTH_4, DEPTH_EXCESSIVE, REJECT}
    Σ = {dot, other}
    q₀ = START
    F = {DEPTH_EXCESSIVE}
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
        state_map = {
            self.START: 0, self.DEPTH_0: 0, self.DEPTH_1: 1, self.DEPTH_2: 2,
            self.DEPTH_3: 3, self.DEPTH_4: 4, self.DEPTH_5: 5, self.DEPTH_6: 6,
            self.DEPTH_EXCESSIVE: 7,
        }
        return state_map.get(state, 0)
    
    def check(self, hostname: str) -> Dict:
        """Execute DFA with multi-label TLD normalization"""
        if not hostname:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "details": None
            }
        
        # Normalize hostname for multi-label TLDs (preprocessing)
        normalized_hostname = normalize_hostname_for_depth(hostname)
        
        # Standard DFA execution loop
        current_state = self.START
        
        for char in normalized_hostname:
            symbol = self._classify_char(char)
            current_state = self._transition(current_state, symbol)
        
        # Check if final state is accepting
        dot_count = self._get_dot_count(current_state)
        subdomain_levels = max(0, dot_count - 1)  # Subtract 1 for domain.tld
        
        # Trigger if subdomain levels exceed max_depth
        triggered = subdomain_levels > self.max_depth
        
        return {
            "triggered": triggered,
            "state": current_state,
            "risk_score": 1.0 if triggered else 0.0,
            "reason": f"Excessive subdomain depth: {subdomain_levels} levels (max {self.max_depth})" if triggered else "Subdomain depth within acceptable limits",
            "details": {
                "hostname": hostname,
                "normalized_hostname": normalized_hostname,
                "dot_count": dot_count,
                "subdomain_levels": subdomain_levels,
                "max_allowed": self.max_depth
            } if triggered else {
                "hostname": hostname,
                "normalized_hostname": normalized_hostname,
                "dot_count": dot_count,
                "subdomain_levels": subdomain_levels
            }
        }


class KeywordDFA:
    """Aho-Corasick style DFA for multi-pattern keyword matching.
    
    Formal Definition: M = (Q, Σ, δ, q₀, F) with precomputed failure function
    Q = State set built from trie over all keywords
    Σ = {a-z, 0-9, -, .}
    q₀ = START
    F = {keyword end states}
    
    Pure DFA with deterministic transitions for each character.
    Detects overlapping keywords efficiently (e.g., "pay" inside "paypal").
    """
    
    START = "START"
    SCANNING = "SCANNING"
    REJECT = "REJECT"
    
    def __init__(self):
        """Initialize Aho-Corasick DFA with suspicious keywords"""
        self.keywords = [
            "login", "secure", "verify", "update", "account",
            "support", "admin", "panel", "auth", "confirm",
            "signin", "password", "passcode", "credential", "2fa",
            "mfa", "otp", "reset", "unlock", "recovery",
            "billing", "payment", "invoice", "wallet", "bank",
            "checkout", "pay", "transaction", "money", "transfer",
            "security", "securecode", "webscr",
            "skype", "americanexpress", "amex", "chase", "itau",
            "hsbc", "lloyds", "lloydstsb", "bbva", "visa",
            "mastercard", "paypal", "paypai", "pay-pal",
            "appleid", "icloud", "office365", "outlook", "onedrive",
            "gmail", "meta", "instagram",
            "tiktok", "venmo", "cashapp", "gpay", "steam",
            "battlenet", "battle.net", "vk", "aol", "malicious", "script"
        ]
        
        # Build AC-style transition table
        self._goto = {}  # goto[state][char] = next_state
        self._fail = {}  # fail[state] = fallback state
        self._output = {}  # output[state] = [keywords found at this state]
        self._build_ac_automaton()
    
    def _build_ac_automaton(self):
        """Build Aho-Corasick automaton from keywords (pure DFA construction)"""
        # Build trie
        trie = {}
        for keyword in self.keywords:
            node = trie
            for char in keyword.lower():
                if char not in node:
                    node[char] = {}
                node = node[char]
            if "$" not in node:
                node["$"] = []
            node["$"].append(keyword)
        
        # Convert trie to state machine (BFS for level-by-level processing)
        state_counter = 0
        state_map = {}  # Map: frozenset(node_id) → state_name
        node_to_state = {}  # Map: id(trie_node) → state
        
        self._goto[self.START] = {}
        self._fail[self.START] = self.START
        self._output[self.START] = []
        
        # Process root's children (depth 1)
        queue = []
        for char, child in trie.items():
            if char != "$":
                state_counter += 1
                child_state = f"S{state_counter}"
                self._goto[self.START][char] = child_state
                self._goto[child_state] = {}
                self._fail[child_state] = self.START
                self._output[child_state] = child.get("$", [])
                queue.append((child_state, child))
        
        # BFS: process remaining nodes
        while queue:
            state, node = queue.pop(0)
            
            for char, child in node.items():
                if char != "$":
                    state_counter += 1
                    child_state = f"S{state_counter}"
                    self._goto[state][char] = child_state
                    self._goto[child_state] = {}
                    self._output[child_state] = child.get("$", [])
                    
                    # Compute failure link
                    fail_state = self._fail[state]
                    while fail_state != self.START and char not in self._goto[fail_state]:
                        fail_state = self._fail[fail_state]
                    
                    if char in self._goto[fail_state]:
                        self._fail[child_state] = self._goto[fail_state][char]
                    else:
                        self._fail[child_state] = self.START
                    
                    # Merge outputs from failure link
                    if self._fail[child_state] in self._output:
                        self._output[child_state].extend(self._output[self._fail[child_state]])
                    
                    queue.append((child_state, child))
    
    def _classify_char(self, char: str) -> str:
        """Map input character to alphabet symbol"""
        char_lower = char.lower()
        if char_lower in "abcdefghijklmnopqrstuvwxyz0123456789-.":
            return char_lower
        return "other"
    
    def _transition_ac(self, state: str, char: str) -> str:
        """Transition function using precomputed goto and fail (pure AC DFA)"""
        while state != self.START and char not in self._goto.get(state, {}):
            state = self._fail.get(state, self.START)
        
        if char in self._goto.get(state, {}):
            return self._goto[state][char]
        else:
            return self.START
    
    def check(self, text: str) -> Dict:
        """Execute AC DFA - pure table-driven approach with failure links"""
        if not text:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "details": None
            }
        
        text_lower = text.lower()
        
        # AC DFA execution loop
        current_state = self.START
        matched_keywords = []
        
        for char in text_lower:
            symbol = self._classify_char(char)
            
            if symbol != "other":
                current_state = self._transition_ac(current_state, symbol)
                
                # Collect outputs from current state and failure links
                if current_state in self._output:
                    for keyword in self._output[current_state]:
                        if keyword not in matched_keywords:
                            matched_keywords.append(keyword)
        
        triggered = len(matched_keywords) > 0
        
        return {
            "triggered": triggered,
            "state": current_state,
            "risk_score": 1.2 if triggered else 0.0,
            "reason": f"Suspicious keyword(s) detected: {', '.join(matched_keywords)}" if triggered else "No suspicious keywords detected",
            "details": {
                "text": text,
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
    """Layer 2 coordinator: combines Confusables, Depth, Keyword, and Punycode DFA checks
    
    All checks now use strict table-driven DFA implementations:
    - ConfusablesDFA: Detects non-ASCII lookalike characters (homograph risk)
    - DepthDFA: Counts dots with multi-label TLD normalization
    - KeywordDFA: Aho-Corasick multi-pattern matching on hostname + path + query
    - PunycodeDFA: Detects "xn--" Punycode prefix
    """
    
    def __init__(self, max_subdomain_depth: int = 2):
        self.homograph_dfa = ConfusablesDFA()
        self.depth_dfa = DepthDFA(max_subdomain_depth)
        self.keyword_dfa = KeywordDFA()
        self.punycode_dfa = PunycodeDFA()
        self.tokenizer = TokenizerDFA()
    
    def analyze(self, url: str) -> Dict:
        """Execute all Layer 2 DFA checks (extended to scan hostname + path + query)"""
        tokens = self.tokenizer.tokenize(url)
        hostname = tokens.get("hostname", "")
        path = tokens.get("path", "")
        query = tokens.get("query", "")
        
        # Run DFAs on hostname
        homograph_result = self.homograph_dfa.check(hostname)
        depth_result = self.depth_dfa.check(hostname)
        punycode_result = self.punycode_dfa.check(hostname)
        
        # Run KeywordDFA on hostname + path + query (combined scan)
        combined_text = f"{hostname}{path}{query}"
        keyword_result = self.keyword_dfa.check(combined_text)
        
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
            "path": path,
            "query": query,
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
        
