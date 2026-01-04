"""Layer 2: Advanced DFA checks (Homographs, Subdomains, Punycode)"""

from typing import Dict
from .tokenizer import TokenizerDFA


class HomographDFA:
    """DFA for IDN homograph detection (non-ASCII characters)"""
    
    START = "START"
    SCANNING = "SCANNING"
    FOUND_NON_ASCII = "FOUND_NON_ASCII"
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    
    def __init__(self):
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
        """Classify character as ASCII, non-ASCII, or dot"""
        if char == ".":
            return "dot"
        elif ord(char) > 127:
            return "non_ascii"
        else:
            return "ascii"
    
    def _transition(self, state: str, char_type: str) -> str:
        """Transition function δ(q, σ) → q'"""
        key = (state, char_type)
        return self._transition_table.get(key, self.REJECT)
    
    def check(self, hostname: str) -> Dict:
        """Execute DFA and return risk assessment"""
        if not hostname:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "details": None
            }
        
        state = self.START
        found_chars = []
        i = 0
        while i < len(hostname):
            char = hostname[i]
            char_type = self._classify_char(char)
            state = self._transition(state, char_type)
            if char_type == "non_ascii" and char not in found_chars:
                found_chars.append(char)
            i += 1
        
        triggered = state in self._accepting_states
        
        return {
            "triggered": triggered,
            "state": state,
            "risk_score": 1.5 if triggered else 0.0,
            "reason": "Non-ASCII characters detected in hostname (IDN homograph attack)" if triggered else "No homograph detected",
            "details": {
                "hostname": hostname,
                "non_ascii_chars": found_chars,
                "char_count": len(found_chars)
            } if triggered else None
        }


class SubdomainDFA:
    """DFA for subdomain pattern analysis (depth, brand jacking, keywords)"""
    
    START = "START"
    PARSING = "PARSING"
    DEPTH_CHECK = "DEPTH_CHECK"
    BRAND_CHECK = "BRAND_CHECK"
    KEYWORD_CHECK = "KEYWORD_CHECK"
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    
    def __init__(self, max_depth: int = 4):
        self.max_depth = max_depth
        
        self._transition_table = {
            (self.START, "dot"): self.PARSING,
            (self.START, "alpha"): self.PARSING,
            (self.START, "digit"): self.PARSING,
            (self.START, "hyphen"): self.PARSING,
            (self.PARSING, "dot"): self.PARSING,
            (self.PARSING, "alpha"): self.PARSING,
            (self.PARSING, "digit"): self.PARSING,
            (self.PARSING, "hyphen"): self.PARSING,
        }
        
        self._accepting_states = {self.DEPTH_CHECK, self.BRAND_CHECK, self.KEYWORD_CHECK, self.ACCEPT}
        
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
        """Transition function δ(q, σ) → q'"""
        key = (state, char_type)
        return self._transition_table.get(key, self.REJECT)
    
    def check(self, hostname: str) -> Dict:
        """Execute DFA and return risk assessment"""
        if not hostname:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "details": None
            }
        
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
        
        if current_part:
            parts.append(current_part)
        
        triggered = False
        issue_type = None
        issue_details = {}
        
        if len(parts) > self.max_depth + 2:
            triggered = True
            issue_type = self.DEPTH_CHECK
            issue_details["excessive_depth"] = True
            issue_details["depth"] = len(parts) - 2
            issue_details["max_allowed"] = self.max_depth
        
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
        
        # Check domain portion (parts[-2]) for brand-keyword combinations (e.g., paypal-secure-verify)
        if len(parts) >= 2 and not triggered:
            domain_portion = parts[-2].lower()
            for brand in self.common_brands:
                if brand in domain_portion:
                    # Check if domain also contains suspicious keywords
                    for keyword in self.suspicious_keywords:
                        if keyword in domain_portion and keyword != brand:
                            triggered = True
                            issue_type = self.BRAND_CHECK
                            issue_details["brand_jacking"] = True
                            issue_details["brand_with_keywords"] = f"{brand} + {keyword}"
                            issue_details["detected_in_domain"] = domain_portion
                            break
                    if triggered:
                        break
        
        if len(parts) >= 3 and not triggered:
            subdomain_str = '.'.join(parts[:-2]).lower()
            for keyword in self.suspicious_keywords:
                if keyword in subdomain_str:
                    triggered = True
                    issue_type = self.KEYWORD_CHECK
                    issue_details["suspicious_keyword"] = True
                    issue_details["keyword"] = keyword
                    break
        
        final_state = issue_type if triggered else self.ACCEPT
        risk_score = 1.2 if triggered else 0.0
        
        # Generate reason/explanation
        reason = ""
        if triggered:
            if "brand_jacking" in issue_details:
                if "brand_with_keywords" in issue_details:
                    reason = f"Brand jacking detected: {issue_details['brand_with_keywords']} in domain '{issue_details.get('detected_in_domain', '')}'"
                else:
                    reason = f"Brand jacking detected: brand '{issue_details.get('brand_in_subdomain', '')}' in subdomain"
            elif "suspicious_keyword" in issue_details:
                reason = f"Suspicious keyword detected in subdomain: '{issue_details.get('keyword', '')}'"
            elif "excessive_depth" in issue_details:
                reason = f"Excessive subdomain depth: {issue_details.get('depth', 0)} levels (max {issue_details.get('max_allowed', 0)})"
        else:
            reason = "No suspicious subdomain patterns detected"
        
        return {
            "triggered": triggered,
            "state": final_state,
            "risk_score": risk_score,
            "reason": reason,
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


class PunycodeDFA:
    """DFA for Punycode (xn--) detection"""
    
    START = "START"
    SCANNING = "SCANNING"
    FOUND_X = "FOUND_X"
    FOUND_N = "FOUND_N"
    FOUND_HYPHEN = "FOUND_HYPHEN"
    FOUND_XN_PREFIX = "FOUND_XN_PREFIX"
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    
    def __init__(self):
        self._transition_table = {
            (self.START, "x"): self.FOUND_X,
            (self.START, "n"): self.SCANNING,
            (self.START, "-"): self.SCANNING,
            (self.START, "other"): self.SCANNING,
            (self.START, "dot"): self.SCANNING,
            (self.FOUND_X, "x"): self.FOUND_X,
            (self.FOUND_X, "n"): self.FOUND_N,
            (self.FOUND_X, "-"): self.SCANNING,
            (self.FOUND_X, "other"): self.SCANNING,
            (self.FOUND_X, "dot"): self.SCANNING,
            (self.FOUND_N, "x"): self.FOUND_X,
            (self.FOUND_N, "n"): self.SCANNING,
            (self.FOUND_N, "-"): self.FOUND_HYPHEN,
            (self.FOUND_N, "other"): self.SCANNING,
            (self.FOUND_N, "dot"): self.SCANNING,
            (self.FOUND_HYPHEN, "x"): self.FOUND_XN_PREFIX,
            (self.FOUND_HYPHEN, "n"): self.FOUND_XN_PREFIX,
            (self.FOUND_HYPHEN, "-"): self.FOUND_XN_PREFIX,
            (self.FOUND_HYPHEN, "other"): self.FOUND_XN_PREFIX,
            (self.FOUND_HYPHEN, "dot"): self.SCANNING,
            (self.FOUND_XN_PREFIX, "x"): self.FOUND_XN_PREFIX,
            (self.FOUND_XN_PREFIX, "n"): self.FOUND_XN_PREFIX,
            (self.FOUND_XN_PREFIX, "-"): self.FOUND_XN_PREFIX,
            (self.FOUND_XN_PREFIX, "other"): self.FOUND_XN_PREFIX,
            (self.FOUND_XN_PREFIX, "dot"): self.SCANNING,
            (self.SCANNING, "x"): self.FOUND_X,
            (self.SCANNING, "n"): self.SCANNING,
            (self.SCANNING, "-"): self.SCANNING,
            (self.SCANNING, "other"): self.SCANNING,
            (self.SCANNING, "dot"): self.SCANNING,
        }
        
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
        """Transition function δ(q, σ) → q'"""
        key = (state, char_type)
        return self._transition_table.get(key, self.REJECT)
    
    def check(self, hostname: str) -> Dict:
        """Execute DFA and return risk assessment"""
        if not hostname:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "details": None
            }
        
        hostname_lower = hostname.lower()
        state = self.START
        punycode_parts = []
        current_part = ""
        found_punycode_in_part = False
        i = 0
        
        while i < len(hostname_lower):
            char = hostname_lower[i]
            char_type = self._classify_char(char)
            
            if char == ".":
                if found_punycode_in_part and current_part:
                    punycode_parts.append(current_part)
                current_part = ""
                found_punycode_in_part = False
                state = self.SCANNING
            else:
                current_part += char
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
                    state = self._transition(state, char_type)
                else:
                    state = self._transition(state, char_type)
            i += 1
        
        if found_punycode_in_part and current_part:
            punycode_parts.append(current_part)
        
        triggered = len(punycode_parts) > 0
        
        return {
            "triggered": triggered,
            "state": self.FOUND_XN_PREFIX if triggered else self.ACCEPT,
            "risk_score": 1.3 if triggered else 0.0,
            "reason": f"Punycode encoding detected in {len(punycode_parts)} domain part(s) - may indicate homograph attack" if triggered else "No punycode detected",
            "details": {
                "hostname": hostname,
                "punycode_parts": punycode_parts,
                "punycode_count": len(punycode_parts),
                "warning": "Punycode encoding detected - may indicate homograph attack"
            } if triggered else None
        }


class Layer2:
    """Layer 2 coordinator: combines Homograph, Subdomain, and Punycode DFA checks"""
    
    def __init__(self, max_subdomain_depth: int = 4):
        self.homograph_dfa = HomographDFA()
        self.subdomain_dfa = SubdomainDFA(max_subdomain_depth)
        self.punycode_dfa = PunycodeDFA()
        self.tokenizer = TokenizerDFA()
    
    def analyze(self, url: str) -> Dict:
        """Execute all Layer 2 DFA checks and aggregate results"""
        tokens = self.tokenizer.tokenize(url)
        hostname = tokens.get("hostname", "")
        
        homograph_result = self.homograph_dfa.check(hostname)
        subdomain_result = self.subdomain_dfa.check(hostname)
        punycode_result = self.punycode_dfa.check(hostname)
        
        triggered_count = sum([
            1 if homograph_result["triggered"] else 0,
            1 if subdomain_result["triggered"] else 0,
            1 if punycode_result["triggered"] else 0,
        ])
        
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
                    "reason": homograph_result.get("reason", ""),
                    "details": homograph_result["details"]
                },
                "subdomain": {
                    "triggered": subdomain_result["triggered"],
                    "state": subdomain_result["state"],
                    "risk_score": subdomain_result["risk_score"],
                    "reason": subdomain_result.get("reason", ""),
                    "details": subdomain_result["details"]
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
            "total_checks": 3,
            "layer_risk_score": layer_risk_score
        }
