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
    """DFA for dynamic DNS pattern detection (excessive params, high digit ratio)"""
    
    START = "START"
    ANALYZING_HOSTNAME = "ANALYZING_HOSTNAME"
    COUNTING_PARAMS = "COUNTING_PARAMS"
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    
    def __init__(self, max_query_params: int = 5, max_digit_ratio: float = 0.4):
        self.max_query_params = max_query_params
        self.max_digit_ratio = max_digit_ratio
        
        self._transition_table = {
            (self.START, "digit"): self.ANALYZING_HOSTNAME,
            (self.START, "alpha"): self.ANALYZING_HOSTNAME,
            (self.START, "other"): self.ANALYZING_HOSTNAME,
            (self.ANALYZING_HOSTNAME, "digit"): self.ANALYZING_HOSTNAME,
            (self.ANALYZING_HOSTNAME, "alpha"): self.ANALYZING_HOSTNAME,
            (self.ANALYZING_HOSTNAME, "other"): self.ANALYZING_HOSTNAME,
        }
        
        self._accepting_states = {self.ACCEPT}
    
    def _classify_char(self, char: str) -> str:
        """Classify character type"""
        if char.isdigit():
            return "digit"
        elif char.isalpha():
            return "alpha"
        elif char == "&":
            return "ampersand"
        else:
            return "other"
    
    def _transition(self, state: str, char_type: str) -> str:
        """Transition function δ(q, σ) → q'"""
        key = (state, char_type)
        return self._transition_table.get(key, self.REJECT)
    
    def check(self, hostname: str, query: str) -> Dict:
        """Execute DFA and return risk assessment"""
        if not hostname and not query:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "details": None
            }
        
        issues = []
        triggered = False
        
        param_count = 0
        if query:
            state = self.START
            i = 0
            param_count = 1
            
            while i < len(query):
                char = query[i]
                char_type = self._classify_char(char)
                state = self._transition(state, char_type)
                if char == "&":
                    param_count += 1
                i += 1
            
            if param_count > self.max_query_params:
                issues.append(f"Excessive query parameters ({param_count} > {self.max_query_params})")
                triggered = True
        
        digit_ratio = 0.0
        if hostname:
            state = self.START
            digit_count = 0
            alpha_count = 0
            i = 0
            
            while i < len(hostname):
                char = hostname[i]
                char_type = self._classify_char(char)
                state = self._transition(state, char_type)
                
                if char_type == "digit":
                    digit_count += 1
                elif char_type == "alpha":
                    alpha_count += 1
                i += 1
            
            total_alnum = digit_count + alpha_count
            if total_alnum > 0:
                digit_ratio = digit_count / total_alnum
                
                if digit_ratio > self.max_digit_ratio:
                    issues.append(f"High digit ratio in hostname ({digit_ratio:.1%} > {self.max_digit_ratio:.0%})")
                    triggered = True
        
        final_state = self.ACCEPT if triggered else self.REJECT
        
        # Generate reason/explanation
        reason = ""
        if triggered:
            if issues:
                reason = "; ".join(issues)
            else:
                reason = "Dynamic DNS patterns or excessive query parameters detected"
        else:
            reason = "No dynamic DNS patterns or excessive parameters detected"
        
        return {
            "triggered": triggered,
            "state": final_state,
            "risk_score": 1.5 if triggered else 0.0,
            "reason": reason,
            "details": {
                "hostname": hostname,
                "query_param_count": param_count,
                "digit_ratio": f"{digit_ratio:.1%}",
                "issues": "; ".join(issues),
                "warning": "Dynamic DNS pattern or excessive parameters detected"
            } if triggered else {
                "hostname": hostname,
                "query_param_count": param_count,
                "digit_ratio": f"{digit_ratio:.1%}"
            }
        }


class RedirectDFA:
    """DFA for redirect parameter detection (url=, redirect=, next=, etc.)"""
    
    START = "START"
    READING_PARAM_NAME = "READING_PARAM_NAME"
    FOUND_EQUALS = "FOUND_EQUALS"
    FOUND_REDIRECT_PARAM = "FOUND_REDIRECT_PARAM"
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    
    def __init__(self):
        self.redirect_params = {
            "url", "redirect", "redirecturl", "redirecturi",
            "next", "goto", "link", "target", "destination",
            "return", "returnurl", "returnuri",
            "continue", "continueurl", "forward", "forwardurl",
            "redir", "rurl", "dest", "out", "to"
        }
        
        self._transition_table = {
            (self.START, "alpha"): self.READING_PARAM_NAME,
            (self.START, "other"): self.START,
            (self.READING_PARAM_NAME, "alpha"): self.READING_PARAM_NAME,
            (self.READING_PARAM_NAME, "equals"): self.FOUND_EQUALS,
            (self.READING_PARAM_NAME, "ampersand"): self.START,
            (self.READING_PARAM_NAME, "other"): self.READING_PARAM_NAME,
            (self.FOUND_EQUALS, "alpha"): self.FOUND_EQUALS,
            (self.FOUND_EQUALS, "ampersand"): self.START,
            (self.FOUND_EQUALS, "other"): self.FOUND_EQUALS,
            (self.FOUND_REDIRECT_PARAM, "alpha"): self.FOUND_REDIRECT_PARAM,
            (self.FOUND_REDIRECT_PARAM, "equals"): self.FOUND_REDIRECT_PARAM,
            (self.FOUND_REDIRECT_PARAM, "ampersand"): self.FOUND_REDIRECT_PARAM,
            (self.FOUND_REDIRECT_PARAM, "other"): self.FOUND_REDIRECT_PARAM,
        }
        
        self._accepting_states = {self.FOUND_REDIRECT_PARAM}
    
    def _classify_char(self, char: str) -> str:
        """Classify character type"""
        if char.isalpha():
            return "alpha"
        elif char == "=":
            return "equals"
        elif char == "&":
            return "ampersand"
        else:
            return "other"
    
    def _transition(self, state: str, char_type: str) -> str:
        """Transition function δ(q, σ) → q'"""
        key = (state, char_type)
        return self._transition_table.get(key, self.REJECT)
    
    def check(self, query: str) -> Dict:
        """Execute DFA and return risk assessment"""
        if not query:
            return {
                "triggered": False,
                "state": self.REJECT,
                "risk_score": 0.0,
                "details": None
            }
        
        state = self.START
        current_param_name = ""
        found_redirect_params = []
        i = 0
        
        while i < len(query):
            char = query[i]
            char_type = self._classify_char(char)
            prev_state = state
            state = self._transition(state, char_type)
            
            if state == self.READING_PARAM_NAME:
                if char_type == "alpha":
                    current_param_name += char.lower()
            elif prev_state == self.READING_PARAM_NAME and char_type == "equals":
                if current_param_name in self.redirect_params:
                    found_redirect_params.append(current_param_name)
                    state = self.FOUND_REDIRECT_PARAM
                current_param_name = ""
            elif char_type == "ampersand":
                current_param_name = ""
            i += 1
        
        if current_param_name and current_param_name in self.redirect_params:
            found_redirect_params.append(current_param_name)
            state = self.FOUND_REDIRECT_PARAM
        
        triggered = len(found_redirect_params) > 0
        
        reason = ""
        if triggered:
            params_str = ", ".join(found_redirect_params)
            reason = f"Redirect parameters detected: {params_str} - possible open redirect vulnerability"
        else:
            reason = "No redirect parameters detected"
        
        return {
            "triggered": triggered,
            "state": self.FOUND_REDIRECT_PARAM if triggered else self.ACCEPT,
            "risk_score": 1.8 if triggered else 0.0,
            "reason": reason,
            "details": {
                "query": query,
                "redirect_params": found_redirect_params,
                "param_count": len(found_redirect_params),
                "warning": "Redirect parameter detected - possible open redirect vulnerability"
            } if triggered else None
        }


class Layer3:
    """Layer 3 coordinator: combines Chained, Dynamic, and Redirect DFA checks"""
    
    def __init__(self):
        self.chained_dfa = ChainedDFA()
        self.dynamic_dfa = DynamicDFA()
        self.redirect_dfa = RedirectDFA()
        self.tokenizer = TokenizerDFA()
    
    def analyze(self, url: str) -> Dict:
        """Execute all Layer 3 DFA checks and aggregate results"""
        tokens = self.tokenizer.tokenize(url)
        
        query = tokens.get("query", "")
        path = tokens.get("path", "")
        hostname = tokens.get("hostname", "")
        
        chained_result = self.chained_dfa.check(query, path)
        dynamic_result = self.dynamic_dfa.check(hostname, query)
        redirect_result = self.redirect_dfa.check(query)
        
        triggered_count = sum([
            1 if chained_result["triggered"] else 0,
            1 if dynamic_result["triggered"] else 0,
            1 if redirect_result["triggered"] else 0,
        ])
        
        layer_risk_score = (
            chained_result["risk_score"] +
            dynamic_result["risk_score"] +
            redirect_result["risk_score"]
        )
        
        return {
            "layer": "Layer 3 (Threat)",
            "query": query,
            "path": path,
            "hostname": hostname,
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
                }
            },
            "triggered_count": triggered_count,
            "total_checks": 3,
            "layer_risk_score": layer_risk_score
        }
