from typing import Dict
from enum import Enum


class TokenType(Enum):
    """URL token categories"""
    SCHEMA = "schema"
    HOSTNAME = "hostname"
    PATH = "path"
    QUERY = "query"
    FRAGMENT = "fragment"


class TokenizerDFA:
    """DFA for URL tokenization - Formal automata implementation"""
    
    def __init__(self):
        self.reset()
        self._build_transition_table()
    
    def reset(self):
        """Initialize DFA state"""
        self.state = "INIT"
        self.current_token = ""
        self.tokens = {
            TokenType.SCHEMA: "",
            TokenType.HOSTNAME: "",
            TokenType.PATH: "",
            TokenType.QUERY: "",
            TokenType.FRAGMENT: ""
        }
    
    def _build_transition_table(self):
        """Build state transition table for table-driven DFA"""
        # Transition table: {state: {char_type: (next_state, action)}}
        self.transitions = {
            "INIT": {
                "alphanum": ("SCHEMA", self._append_token),
                "scheme_char": ("SCHEMA", self._append_token),
                "other": ("INIT", self._noop)
            },
            "SCHEMA": {
                "alphanum": ("SCHEMA", self._append_token),
                "scheme_char": ("SCHEMA", self._append_token),
                "colon": ("COLON", self._append_colon),
                "slash": ("PATH", self._finalize_hostname_start_path_from_schema),
                "other": ("HOSTNAME", self._schema_to_hostname_append)
            },
            "COLON": {
                "slash": ("SLASH1", self._noop),
                "other": ("HOSTNAME", self._move_to_hostname_with_colon)
            },
            "SLASH1": {
                "slash": ("AFTER_SCHEMA", self._finalize_schema),
                "other": ("HOSTNAME", self._move_to_hostname_with_slash)
            },
            "AFTER_SCHEMA": {
                "slash": ("AFTER_SCHEMA", self._noop),
                "other": ("HOSTNAME", self._append_token)
            },
            "HOSTNAME": {
                "slash": ("PATH", self._finalize_hostname_start_path),
                "question": ("QUERY", self._finalize_hostname),
                "hash": ("END", self._finalize_hostname),
                "other": ("HOSTNAME", self._append_token)
            },
            "PATH": {
                "question": ("QUERY", self._finalize_path),
                "hash": ("END", self._finalize_path),
                "other": ("PATH", self._append_token)
            },
            "QUERY": {
                "hash": ("FRAGMENT", self._finalize_query),
                "other": ("QUERY", self._append_token)
            },
            "FRAGMENT": {
                "other": ("FRAGMENT", self._append_token)
            },
            "END": {}
        }
    
    def _classify_char(self, char: str) -> str:
        """Classify character type for transition table lookup"""
        if char.isalnum():
            return "alphanum"
        elif char in ['+', '-', '.']:
            return "scheme_char"
        elif char == ':':
            return "colon"
        elif char == '/':
            return "slash"
        elif char == '?':
            return "question"
        elif char == '#':
            return "hash"
        else:
            return "other"
    
    # Action functions for state transitions
    def _noop(self, char: str):
        """No operation"""
        pass
    
    def _append_colon(self, char: str):
        """Append colon to schema token"""
        self.current_token += ":"
    
    def _append_token(self, char: str):
        """Append character to current token"""
        self.current_token += char
    
    def _reset_and_append(self, char: str):
        """Reset token and append character (for transitioning from SCHEMA to HOSTNAME)"""
        self.current_token = char

    def _schema_to_hostname_append(self, char: str):
        """Move accumulated schema-like chars into hostname when no colon is present"""
        self.current_token = self.current_token + char

    def _finalize_hostname_start_path_from_schema(self, char: str):
        """Finalize hostname (no scheme) and start path at first slash"""
        self.tokens[TokenType.HOSTNAME] = self.current_token
        self.current_token = "/"
    
    def _move_to_hostname_with_colon(self, char: str):
        """Move accumulated schema + colon to hostname, append current char"""
        self.current_token = self.current_token + ':' + char
    
    def _move_to_hostname_with_slash(self, char: str):
        """Move accumulated schema + :/ to hostname, append current char"""
        self.current_token = self.current_token + ':/' + char
    
    def _finalize_schema(self, char: str):
        """Save schema token and reset"""
        self.tokens[TokenType.SCHEMA] = self.current_token
        self.current_token = ""
    
    def _finalize_hostname(self, char: str):
        """Save hostname token and reset"""
        self.tokens[TokenType.HOSTNAME] = self.current_token
        self.current_token = ""
    
    def _finalize_hostname_start_path(self, char: str):
        """Save hostname and start path with /"""
        self.tokens[TokenType.HOSTNAME] = self.current_token
        self.current_token = "/"
    
    def _finalize_path(self, char: str):
        """Save path token and reset"""
        self.tokens[TokenType.PATH] = self.current_token
        self.current_token = ""
    
    def _finalize_query(self, char: str):
        """Save query token and reset"""
        self.tokens[TokenType.QUERY] = self.current_token
        self.current_token = ""
    
    def _finalize_fragment(self, char: str):
        """Save fragment token and reset"""
        self.tokens[TokenType.FRAGMENT] = self.current_token
        self.current_token = ""
    
    def preprocess(self, url: str) -> str:
        """Normalize and decode URL"""
        url = url.strip().lower()
        try:
            from urllib.parse import unquote
            url = unquote(url)
        except Exception:
            pass
        return url
    
    def tokenize(self, url: str) -> Dict[str, str]:
        """Process URL through DFA states using transition table"""
        self.reset()
        cleaned_url = self.preprocess(url)
        
        for char in cleaned_url:
            if self.state == "END":
                break
            
            char_type = self._classify_char(char)
            
            # Get transition for current state
            state_transitions = self.transitions.get(self.state, {})
            
            # Find matching transition (try specific char_type, then 'other')
            if char_type in state_transitions:
                next_state, action = state_transitions[char_type]
            elif "other" in state_transitions:
                next_state, action = state_transitions["other"]
            else:
                # No valid transition, stay in current state
                continue
            
            # Execute action and transition to next state
            action(char)
            self.state = next_state
        
        # Finalize remaining token based on end state
        if self.state == "SCHEMA" and self.current_token:
            self.tokens[TokenType.HOSTNAME] = self.current_token
        elif self.state == "HOSTNAME" and self.current_token:
            self.tokens[TokenType.HOSTNAME] = self.current_token
        elif self.state == "PATH" and self.current_token:
            self.tokens[TokenType.PATH] = self.current_token
        elif self.state == "QUERY" and self.current_token:
            self.tokens[TokenType.QUERY] = self.current_token
        elif self.state == "FRAGMENT" and self.current_token:
            self.tokens[TokenType.FRAGMENT] = self.current_token
        
        return {
            "schema": self.tokens[TokenType.SCHEMA],
            "hostname": self.tokens[TokenType.HOSTNAME],
            "path": self.tokens[TokenType.PATH],
            "query": self.tokens[TokenType.QUERY],
            "fragment": self.tokens[TokenType.FRAGMENT]
        }
    
    def get_hostname_components(self, hostname: str) -> Dict[str, str]:
        """Parse hostname into subdomain, domain, and TLD using character-by-character DFA"""
        if not hostname:
            return {"subdomain": "", "domain": "", "tld": ""}
        
        # Mini-DFA to parse hostname components without split()
        state = "BUILDING"
        parts = []
        current_part = ""
        
        for char in hostname:
            if state == "BUILDING":
                if char == '.':
                    if current_part:  # Don't add empty parts
                        parts.append(current_part)
                        current_part = ""
                    state = "DOT_SEEN"
                else:
                    current_part += char
            
            elif state == "DOT_SEEN":
                if char == '.':
                    # Consecutive dots - treat as part of the component
                    if current_part:
                        parts.append(current_part)
                        current_part = ""
                else:
                    current_part += char
                    state = "BUILDING"
        
        # Add final part
        if current_part:
            parts.append(current_part)
        
        # Extract subdomain, domain, and TLD from parts list
        num_parts = len(parts)
        
        if num_parts == 0:
            return {"subdomain": "", "domain": "", "tld": ""}
        elif num_parts == 1:
            return {"subdomain": "", "domain": parts[0], "tld": ""}
        elif num_parts == 2:
            return {"subdomain": "", "domain": parts[0], "tld": parts[1]}
        else:
            # Reconstruct subdomain by concatenating all parts except last two
            subdomain = ""
            for i in range(num_parts - 2):
                if i > 0:
                    subdomain += "."
                subdomain += parts[i]
            
            return {
                "subdomain": subdomain,
                "domain": parts[num_parts - 2],
                "tld": parts[num_parts - 1]
            }