"""  
===========================================
LAYER 3 - THREAT DFA
===========================================
Threat pattern checks using specialized automata:

Chained URL DFA: Detects URLs within URLs
  - Scans Query and Path tokens for embedded URLs
  - Pattern: ...&redirect_url=http://... or ...&url=http://...
  - Attack: Legitimate-looking URL contains redirect to attacker's domain
  - States: SCAN_QUERY -> DETECT_URL_PATTERN -> ACCEPT/REJECT

Dynamic DNS DFA: Identifies dynamic URL generation patterns
  - Excessive query parameters (>5): Sign of obfuscation
  - High digit ratio in hostname (>40%): Dynamic DNS services or masking
  - Dynamic patterns: 3+ consecutive digits or alternating letters/digits
  - Attackers use dynamic DNS to evade detection and rotate domains

Redirect Parameter DFA: Flags common redirect parameters
  - Common redirect params: ?url=, ?redirect=, ?next=, ?goto=, ?link=
  - Attack: URL contains parameter pointing to attacker's site
  - Example: legitimate.com?redirect=attacker.com
  - Often combined with obfuscation or encoding
import re


# ========================================
# CHAINED URL DFA
# ========================================

class ChainedDFA:
    """
    DFA for detecting chained URLs (URLs within URLs).
    
    States: INIT -> SCAN_QUERY_PATH -> DETECT_URL_PATTERN -> ACCEPT/REJECT
    Transitions: Look for http://, https://, //, or www. patterns in query/path
    
    Attack Vector:
    - Attacker embeds another URL in the query parameters
    - Example: https://legitimate.com?page=http://attacker.com
    - User may not notice the actual destination URL
    - Combined with URL shorteners or obfuscation for bypass
    
    Detection Strategy:
    - Scan query parameters for URL patterns
    - Flag if any URL found (indicates parameter passing)
    - Multiple URLs = higher suspicion (redirect chaining)
    """
    
    def check(self, query: str, path: str) -> Dict:
        """Return dict with triggered status and reason"""
        text_to_check = f"{path}?{query}" if query else path
        
        if not text_to_check:
            return {"triggered": False, "reason": None, "value": None}
        
        url_patterns = [
            r'https?://[^\s&"\'<>]+',
            r'//[^\s&"\'<>]+',
            r'www\.[^\s&"\'<>]+',
        ]
        
        found_urls = []
        for pattern in url_patterns:
            matches = re.findall(pattern, text_to_check, re.IGNORECASE)
            if matches:
                found_urls.extend(matches)
        
        if found_urls:
            unique_urls = list(set(found_urls))
            return {
                "triggered": True,
                "reason": f"Chained URLs detected in query/path: {unique_urls[:3]}",
                "value": unique_urls
            }
        
        return {"triggered": False, "reason": None, "value": None}


# ========================================
# DYNAMIC DNS DFA
# ========================================

class DynamicDFA:
    """
    DFA for detecting dynamic DNS and URL generation patterns.
    
    States: INIT -> ANALYZE_HOSTNAME -> ANALYZE_PARAMS -> ACCEPT/REJECT
    Transitions: Check digit ratio, query param count, dynamic patterns
    
    Attack Vectors:
    1. Dynamic DNS Services:
       - Services like noip.com allow free dynamic domains
       - Attackers rotate IPs to evade blocklists
       - High digit content in domain (e.g., ip173928374.com)
    
    2. Excessive Parameters:
       - >5 query parameters unusual for normal sites
       - Attackers obfuscate intent with many decoy parameters
       - Used for analytics evasion and fingerprinting
    
    3. Digit Overloading:
       - High ratio of digits (>40%) in hostname
       - Legitimate domains rarely use this pattern
       - Dynamic DNS and IP-based attacks often use numerical domains
    """
    
    def __init__(self):
        self.max_query_params = 5
        self.max_digit_ratio = 0.4
    
    def check(self, hostname: str, query: str) -> Dict:
        """Return dict with triggered status and reason"""
        issues = []
        
        # Check query parameter count
        if query:
            params = query.split('&')
            if len(params) > self.max_query_params:
                issues.append(f"Excessive query parameters ({len(params)})")
        
        # Check digit ratio in hostname
        if hostname:
            digits = sum(1 for c in hostname if c.isdigit())
            total_chars = len([c for c in hostname if c.isalnum()])
            if total_chars > 0:
                digit_ratio = digits / total_chars
                if digit_ratio > self.max_digit_ratio:
                    issues.append(f"High digit ratio in hostname ({digit_ratio:.2%}), possible dynamic DNS")
        
        # Check for dynamic DNS patterns
        if hostname:
            dynamic_patterns = [
                r'\d{3,}',
                r'[a-z]+\d+[a-z]+\d+',
            ]
            for pattern in dynamic_patterns:
                if re.search(pattern, hostname, re.IGNORECASE):
                    issues.append(f"Dynamic DNS pattern detected in hostname")
                    break
        
        if issues:
            return {
                "triggered": True,
                "reason": "; ".join(issues),
                "value": {
                    "query_param_count": len(query.split('&')) if query else 0,
                    "hostname": hostname
                }
            }
        
        return {
            "triggered": False,
            "reason": None,
            "value": {"query_param_count": len(query.split('&')) if query else 0}
        }


# ========================================
# REDIRECT PARAMETER DFA
# ========================================

class RedirectDFA:
    """
    DFA for detecting redirect parameters in query strings.
    
    States: INIT -> PARSE_QUERY -> DETECT_REDIRECT_PARAMS -> ACCEPT/REJECT
    Transitions: Check parameter names against known redirect patterns
    
    Attack Vector:
    - URL contains parameter with another URL as value
    - Example: site.com?next=http://attacker.com
    - Browser may redirect transparently to attacker's site
    - Often combined with legitimate-looking parent domain
    
    Common Redirect Parameters:
    - url, redirect, next, goto: Direct redirect
    - return, returnurl, continue: Post-action redirect
    - link, target, destination: Forwarding parameters
    - forward, forward_url: Legacy redirect patterns
    
    Why It's Dangerous:
    - Users trust the initial domain
    - Don't notice parameter pointing elsewhere
    - Open redirect vulnerabilities exploited
    - Works with social engineering tactics
    """
    
    def __init__(self):
        self.redirect_params = {
            "url", "redirect", "redirect_url", "redirect_uri",
            "next", "goto", "link", "target", "destination",
            "return", "returnurl", "return_url", "return_uri",
            "continue", "continue_url", "forward", "forward_url"
        }
    
    def check(self, query: str) -> Dict:
        """Return dict with triggered status and reason"""
        if not query:
            return {"triggered": False, "reason": None, "value": None}
        
        params = query.split('&')
        redirect_params_found = []
        
        for param in params:
            param_name = param.split('=')[0].lower().strip()
            if param_name in self.redirect_params:
                redirect_params_found.append(param_name)
        
        if redirect_params_found:
            unique_params = list(set(redirect_params_found))
            return {
                "triggered": True,
                "reason": f"Redirect parameters detected: {', '.join(unique_params)}",
                "value": unique_params
            }
        
        return {"triggered": False, "reason": None, "value": None}


# ========================================
# LAYER 3 COORDINATOR
# ========================================

class Layer3:
    """Combines all Layer 3 threat DFA checks"""
    
    def __init__(self):
        self.chained_dfa = ChainedDFA()
        self.dynamic_dfa = DynamicDFA()
        self.redirect_dfa = RedirectDFA()
        self.tokenizer = TokenizerDFA()
    
    def analyze(self, url: str) -> Dict:
        """Execute all Layer 3 checks and aggregate results"""
        tokens = self.tokenizer.tokenize(url)
        
        chained_check = self.chained_dfa.check(tokens["query"], tokens["path"])
        dynamic_check = self.dynamic_dfa.check(tokens["hostname"], tokens["query"])
        redirect_check = self.redirect_dfa.check(tokens["query"])
        
        triggered_count = sum([
            chained_check["triggered"],
            dynamic_check["triggered"],
            redirect_check["triggered"]
        ])
        
        return {
            "layer": "Layer 3 (Threat)",
            "checks": {
                "chained": chained_check,
                "dynamic": dynamic_check,
                "redirect": redirect_check
            },
            "triggered_count": triggered_count,
            "total_checks": 3
        }

