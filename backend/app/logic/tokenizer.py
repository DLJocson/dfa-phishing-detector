"""
===========================================
TOKENIZER DFA
===========================================
Parses URLs into fundamental components using DFA state machine
Components: Schema (protocol), Hostname, Path, Query
"""

from typing import Dict
from enum import Enum


# ========================================
# TOKEN TYPES
# ========================================

class TokenType(Enum):
    """URL token categories"""
    SCHEMA = "schema"
    HOSTNAME = "hostname"
    PATH = "path"
    QUERY = "query"


# ========================================
# TOKENIZER DFA
# ========================================

class TokenizerDFA:
    """
    DFA for URL tokenization
    States: INIT -> SCHEMA -> AFTER_SCHEMA -> HOSTNAME -> PATH -> QUERY
    """
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        """Initialize DFA state"""
        self.state = "INIT"
        self.current_token = ""
        self.tokens = {
            TokenType.SCHEMA: "",
            TokenType.HOSTNAME: "",
            TokenType.PATH: "",
            TokenType.QUERY: ""
        }
    
    # ----------------------------------------
    # Preprocessing
    # ----------------------------------------
    
    def preprocess(self, url: str) -> str:
        """Normalize and decode URL"""
        url = url.strip().lower()
        try:
            from urllib.parse import unquote
            url = unquote(url)
        except Exception:
            pass
        return url
    
    # ----------------------------------------
    # Main Tokenization Algorithm
    # ----------------------------------------
    
    def tokenize(self, url: str) -> Dict[str, str]:
        """
        Process URL through DFA states
        
        Args:
            url: URL string to parse
        Returns:
            Dict with schema, hostname, path, query tokens
        """
        self.reset()
        cleaned_url = self.preprocess(url)
        
        # DFA state machine loop
        i = 0
        while i < len(cleaned_url):
            char = cleaned_url[i]
            
            # State: INIT (start)
            if self.state == "INIT":
                if char.isalnum() or char in ['+', '-', '.']:
                    self.state = "SCHEMA"
                    self.current_token = char
                else:
                    i += 1
                    continue
            
            # State: SCHEMA (parsing protocol)
            elif self.state == "SCHEMA":
                if char == ':':
                    if cleaned_url[i+1:i+3] == '//':
                        self.tokens[TokenType.SCHEMA] = self.current_token
                        self.state = "AFTER_SCHEMA"
                        self.current_token = ""
                        i += 2
                        continue
                    else:
                        self.current_token += char
                elif char.isalnum() or char in ['+', '-', '.']:
                    self.current_token += char
                else:
                    self.state = "HOSTNAME"
                    self.current_token = char
                    continue
            
            # State: AFTER_SCHEMA (between :// and hostname)
            elif self.state == "AFTER_SCHEMA":
                self.state = "HOSTNAME"
                self.current_token = char
                continue
            
            # State: HOSTNAME (parsing domain)
            elif self.state == "HOSTNAME":
                if char == '/':
                    self.tokens[TokenType.HOSTNAME] = self.current_token
                    self.state = "PATH"
                    self.current_token = "/"
                elif char == '?':
                    self.tokens[TokenType.HOSTNAME] = self.current_token
                    self.state = "QUERY"
                    self.current_token = ""
                elif char == '#':
                    self.tokens[TokenType.HOSTNAME] = self.current_token
                    break
                else:
                    self.current_token += char
            
            # State: PATH (parsing path)
            elif self.state == "PATH":
                if char == '?':
                    self.tokens[TokenType.PATH] = self.current_token
                    self.state = "QUERY"
                    self.current_token = ""
                elif char == '#':
                    self.tokens[TokenType.PATH] = self.current_token
                    break
                else:
                    self.current_token += char
            
            # State: QUERY (parsing query string)
            elif self.state == "QUERY":
                if char == '#':
                    self.tokens[TokenType.QUERY] = self.current_token
                    break
                else:
                    self.current_token += char
            
            i += 1
        
        # Finalize remaining token
        if self.state == "SCHEMA" and self.current_token:
            self.tokens[TokenType.HOSTNAME] = self.current_token
        elif self.state == "HOSTNAME" and self.current_token:
            self.tokens[TokenType.HOSTNAME] = self.current_token
        elif self.state == "PATH" and self.current_token:
            self.tokens[TokenType.PATH] = self.current_token
        elif self.state == "QUERY" and self.current_token:
            self.tokens[TokenType.QUERY] = self.current_token
        
        return {
            "schema": self.tokens[TokenType.SCHEMA],
            "hostname": self.tokens[TokenType.HOSTNAME],
            "path": self.tokens[TokenType.PATH],
            "query": self.tokens[TokenType.QUERY]
        }
    
    # ----------------------------------------
    # Hostname Component Extraction
    # ----------------------------------------
    
    def get_hostname_components(self, hostname: str) -> Dict[str, str]:
        """
        Parse hostname into subdomain, domain, and TLD
        
        Args:
            hostname: Hostname to parse
        Returns:
            Dict with subdomain, domain, tld
        """
        if not hostname:
            return {"subdomain": "", "domain": "", "tld": ""}
        
        parts = hostname.split('.')
        
        if len(parts) == 1:
            return {"subdomain": "", "domain": parts[0], "tld": ""}
        elif len(parts) == 2:
            return {"subdomain": "", "domain": parts[0], "tld": parts[1]}
        else:
            return {
                "subdomain": '.'.join(parts[:-2]),
                "domain": parts[-2],
                "tld": parts[-1]
            }

