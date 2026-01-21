from typing import Dict

# ASCII characters (32-126) 
PRINTABLE_ASCII = set(
    " !\"#$%&'()*+,-./"
    "0123456789"
    ":;<=>?@"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "[\\]^_`"
    "abcdefghijklmnopqrstuvwxyz"
    "{|}~"
)

#this dfa checks for length of the url
#if the url exceeds 75 character threshold, it triggers
class LengthDFA:
    """
    Formal Definition: M = (Q, Σ, δ, q₀, F)
    Q = {START, UNDER_THRESHOLD, OVER_THRESHOLD, REJECT}
    Σ = {char} (any printable ASCII character [32-126])
    q₀ = START
    F = {OVER_THRESHOLD}
    """

    START = "START"
    UNDER_THRESHOLD = "UNDER_THRESHOLD"
    OVER_THRESHOLD = "OVER_THRESHOLD"
    REJECT = "REJECT"

    def __init__(self, threshold: int = 75, debug: bool = False):
        self.threshold = threshold
        self.risk_score = 0.3
        self.debug = debug

        self._transition_table = {
            (self.START, "char"): self.UNDER_THRESHOLD,
            (self.UNDER_THRESHOLD, "char"): self.UNDER_THRESHOLD,
            (self.OVER_THRESHOLD, "char"): self.OVER_THRESHOLD,
        }
        self._accepting_states = {self.OVER_THRESHOLD}

    def _classify_char(self, char: str) -> str:
        if char in PRINTABLE_ASCII:
            return "char"
        return "invalid"

    def _transition(self, state: str, symbol: str, count: int) -> str:
        if symbol == "invalid":
            return self.REJECT
        if state == self.START:
            return self.UNDER_THRESHOLD
        if state == self.UNDER_THRESHOLD:
            return self.OVER_THRESHOLD if count > self.threshold else self.UNDER_THRESHOLD
        if state == self.OVER_THRESHOLD:
            return self.OVER_THRESHOLD
        return self.REJECT

    def check(self, url: str) -> Dict:
        if not url:
            return {
                "triggered": False,
                "state": self.REJECT,
                "reason": "Empty URL",
                "value": 0,
                "threshold": self.threshold,
                "risk_score": 0.0,
            }

        current_state = self.START
        char_count = 0

        for char in url:
            symbol = self._classify_char(char)
            if symbol == "invalid":
                return {
                    "triggered": False,
                    "state": self.REJECT,
                    "reason": f"Invalid character at position {char_count + 1}",
                    "value": char_count,
                    "threshold": self.threshold,
                    "risk_score": 0.0,
                }

            char_count += 1
            current_state = self._transition(current_state, symbol, char_count)

            if current_state == self.OVER_THRESHOLD:
                break

        triggered = current_state in self._accepting_states
        risk_score = self.risk_score if triggered else 0.0
        reason = (
            f"URL length ({char_count}) exceeds threshold ({self.threshold})"
            if triggered
            else f"URL length ({char_count}) within acceptable limits"
        )

        return {
            "triggered": triggered,
            "state": current_state,
            "reason": reason,
            "value": char_count,
            "threshold": self.threshold,
            "risk_score": risk_score,
        }

#this DFA checks for malicious schemas like data: and file: and 
# keeps schemas such as http: and https: as safe
class SchemaDFA:
    def __init__(self, debug: bool = False):
        self.risk_score = 0.8
        self.debug = debug

        # States
        self.START = "START"
        self.H = "H"
        self.HT = "HT"
        self.HTT = "HTT"
        self.HTTP = "HTTP"
        self.HTTPS = "HTTPS"
        # FTP/TFTP states
        self.T = "T"
        self.TF = "TF"
        self.TFT = "TFT"
        self.TFTP = "TFTP"
        self.D = "D"
        self.DA = "DA"
        self.DAT = "DAT"
        self.DATA = "DATA"
        self.F = "F"
        self.FT = "FT"
        self.FTP = "FTP"
        self.FI = "FI"
        self.FIL = "FIL"
        self.FILE = "FILE"
        self.SAFE_HTTP = "SAFE_HTTP"
        self.SAFE_HTTPS = "SAFE_HTTPS"
        self.MALICIOUS_DATA = "MALICIOUS_DATA"
        self.MALICIOUS_FILE = "MALICIOUS_FILE"
        self.MALICIOUS_FTP = "MALICIOUS_FTP"
        self.MALICIOUS_TFTP = "MALICIOUS_TFTP"
        self.REJECT = "REJECT"

        self._transition_table = {
            # Start branching
            (self.START, 'h'): self.H,
            (self.START, 'H'): self.H,
            (self.START, 'd'): self.D,
            (self.START, 'D'): self.D,
            (self.START, 'f'): self.F,
            (self.START, 'F'): self.F,
            (self.START, 't'): self.T,
            (self.START, 'T'): self.T,

            # http/https
            (self.H, 't'): self.HT,
            (self.H, 'T'): self.HT,
            (self.HT, 't'): self.HTT,
            (self.HT, 'T'): self.HTT,
            (self.HTT, 'p'): self.HTTP,
            (self.HTT, 'P'): self.HTTP,
            (self.HTTP, 's'): self.HTTPS,
            (self.HTTP, 'S'): self.HTTPS,
            (self.HTTP, ':'): self.SAFE_HTTP,
            (self.HTTPS, ':'): self.SAFE_HTTPS,

            # tftp
            (self.T, 'f'): self.TF,
            (self.T, 'F'): self.TF,
            (self.TF, 't'): self.TFT,
            (self.TF, 'T'): self.TFT,
            (self.TFT, 'p'): self.TFTP,
            (self.TFT, 'P'): self.TFTP,
            (self.TFTP, ':'): self.MALICIOUS_TFTP,

            # data
            (self.D, 'a'): self.DA,
            (self.D, 'A'): self.DA,
            (self.DA, 't'): self.DAT,
            (self.DA, 'T'): self.DAT,
            (self.DAT, 'a'): self.DATA,
            (self.DAT, 'A'): self.DATA,
            (self.DATA, ':'): self.MALICIOUS_DATA,

            # file
            (self.F, 'i'): self.FI,
            (self.F, 'I'): self.FI,
            (self.FI, 'l'): self.FIL,
            (self.FI, 'L'): self.FIL,
            (self.FIL, 'e'): self.FILE,
            (self.FIL, 'E'): self.FILE,
            (self.FILE, ':'): self.MALICIOUS_FILE,

            # ftp
            (self.F, 't'): self.FT,
            (self.F, 'T'): self.FT,
            (self.FT, 'p'): self.FTP,
            (self.FT, 'P'): self.FTP,
            (self.FTP, ':'): self.MALICIOUS_FTP,
        }

        # Self-loops for terminal states so they consume remaining input
        # This allows full URLs like "data:text/html,..." to be recognized
        for char in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:/?#[]@!$&'()*+,;=._~-":
            self._transition_table[(self.MALICIOUS_DATA, char)] = self.MALICIOUS_DATA
            self._transition_table[(self.MALICIOUS_FILE, char)] = self.MALICIOUS_FILE
            self._transition_table[(self.MALICIOUS_FTP, char)] = self.MALICIOUS_FTP
            self._transition_table[(self.MALICIOUS_TFTP, char)] = self.MALICIOUS_TFTP
            self._transition_table[(self.SAFE_HTTP, char)] = self.SAFE_HTTP
            self._transition_table[(self.SAFE_HTTPS, char)] = self.SAFE_HTTPS

        self._accepting_states = {self.MALICIOUS_DATA, self.MALICIOUS_FILE, self.MALICIOUS_FTP, self.MALICIOUS_TFTP}
        self._safe_states = {self.SAFE_HTTP, self.SAFE_HTTPS}
        self.initial_state = self.START

    def _classify_char(self, char: str) -> str:
        return char

    def _transition(self, state: str, symbol: str) -> str:
        return self._transition_table.get((state, symbol), self.REJECT)

    def check(self, schema: str) -> Dict:
        if not schema:
            return {
                "triggered": False,
                "state": self.REJECT,
                "reason": "URL missing protocol/schema",
                "value": None,
                "risk_score": 0.0,
            }

        current_state = self.initial_state
        detected_schema = ""

        for char in schema:
            symbol = self._classify_char(char)
            current_state = self._transition(current_state, symbol)
            detected_schema += char
            if current_state == self.REJECT:
                break

        triggered = current_state in self._accepting_states
        risk_score = self.risk_score if triggered else 0.0

        if current_state == self.MALICIOUS_DATA:
            reason = "Malicious schema detected: data:"
        elif current_state == self.MALICIOUS_FILE:
            reason = "Malicious schema detected: file:"
        elif current_state == self.MALICIOUS_FTP:
            reason = "Malicious schema detected: ftp:"
        elif current_state == self.MALICIOUS_TFTP:
            reason = "Malicious schema detected: tftp:"
        elif current_state == self.SAFE_HTTP:
            reason = "Safe schema detected: http:"
        elif current_state == self.SAFE_HTTPS:
            reason = "Safe schema detected: https:"
        else:
            reason = "Unknown/Invalid schema"

        if self.debug:
            print(f"Schema DFA -> input: {schema}, path: {detected_schema}, final: {current_state}, triggered: {triggered}")

        return {
            "triggered": triggered,
            "state": current_state,
            "reason": reason,
            "value": schema,
            "risk_score": risk_score,
        }

#this dfa detects suspicious tlds such as .zip, .exe, .mov, .tk, .xyz
class TLDDFA:
    """Table-driven DFA for high-risk TLD detection (matches SchemaDFA style)."""

    def __init__(self, debug: bool = False):
        self.risk_score = 1.0
        self.debug = debug

        # States
        self.START = "START"
        self.Z = "Z"
        self.ZI = "ZI"
        self.ZIP = "ZIP"
        self.E = "E"
        self.EX = "EX"
        self.EXE = "EXE"
        self.M = "M"
        self.MO = "MO"
        self.MOV = "MOV"
        self.T = "T"
        self.TK = "TK"
        self.X = "X"
        self.XY = "XY"
        self.XYZ = "XYZ"
        self.MALICIOUS = "MALICIOUS"
        self.REJECT = "REJECT"

        self._transition_table = {
            # zip
            (self.START, 'z'): self.Z,
            (self.START, 'Z'): self.Z,
            (self.START, '.'): self.START,  # skip leading dots
            (self.Z, 'i'): self.ZI,
            (self.Z, 'I'): self.ZI,
            (self.ZI, 'p'): self.ZIP,
            (self.ZI, 'P'): self.ZIP,
            
            # exe
            (self.START, 'e'): self.E,
            (self.START, 'E'): self.E,
            (self.E, 'x'): self.EX,
            (self.E, 'X'): self.EX,
            (self.EX, 'e'): self.EXE,
            (self.EX, 'E'): self.EXE,
            
            # mov
            (self.START, 'm'): self.M,
            (self.START, 'M'): self.M,
            (self.M, 'o'): self.MO,
            (self.M, 'O'): self.MO,
            (self.MO, 'v'): self.MOV,
            (self.MO, 'V'): self.MOV,
            
            # tk
            (self.START, 't'): self.T,
            (self.START, 'T'): self.T,
            (self.T, 'k'): self.TK,
            (self.T, 'K'): self.TK,
            
            # xyz
            (self.START, 'x'): self.X,
            (self.START, 'X'): self.X,
            (self.X, 'y'): self.XY,
            (self.X, 'Y'): self.XY,
            (self.XY, 'z'): self.XYZ,
            (self.XY, 'Z'): self.XYZ,
        }

        self._complete_states = {self.ZIP, self.EXE, self.MOV, self.TK, self.XYZ}
        self._accepting_states = {self.MALICIOUS}

    def _classify_char(self, char: str) -> str:
        return char

    def _transition(self, state: str, symbol: str) -> str:
        return self._transition_table.get((state, symbol), self.REJECT)

    def check(self, tld: str) -> Dict:
        if not tld:
            return {
                "triggered": False,
                "state": self.REJECT,
                "reason": "No TLD provided",
                "value": None,
                "risk_score": 0.0,
            }

        current_state = self.START
        detected_tld = ""

        for char in tld:
            if char == '.':
                if not detected_tld:  # skip leading dots
                    continue
                else:
                    break  # stop at trailing dots
            
            symbol = self._classify_char(char)
            current_state = self._transition(current_state, symbol)
            detected_tld += char
            
            if current_state == self.REJECT:
                break

        # Check if we ended in a complete TLD state
        if current_state in self._complete_states:
            final_state = self.MALICIOUS
            triggered = True
            risk_score = self.risk_score
            reason = f"High-risk TLD detected: .{detected_tld}"
        else:
            final_state = self.REJECT
            triggered = False
            risk_score = 0.0
            if detected_tld:
                reason = f"Unknown TLD (not in high-risk list): .{detected_tld}"
            else:
                reason = "No TLD provided"

        if self.debug:
            print(f"TLD DFA -> input: {tld}, detected: {detected_tld}, final: {final_state}, triggered: {triggered}")

        return {
            "triggered": triggered,
            "state": final_state,
            "reason": reason,
            "value": detected_tld,
            "risk_score": risk_score,
        }


# ==============================================================================
# LAYER 1 COORDINATOR
# ==============================================================================
# Purpose: Orchestrate all Layer 1 DFA checks and aggregate results
# 
# This class combines:
#   1. LengthDFA - URL length anomaly detection
#   2. SchemaDFA - Malicious protocol detection  
#   3. TLDDFA - High-risk TLD detection
#
# Total possible risk score: 0.3 + 0.8 + 1.0 = 2.1
# ==============================================================================

class Layer1:
    """
    Layer 1 coordinator: combines Length, Schema, and TLD DFA checks.
    
    This class orchestrates all three basic DFA checks and aggregates
    their results into a single layer report.
    """
    
    def __init__(self, length_threshold: int = 75, debug: bool = False):
        """
        Initialize Layer 1 with all three DFAs.
        
        Args:
            length_threshold: Maximum acceptable URL length (default: 75)
            debug: Enable state transition tracing for all DFAs
        """
        self.debug = debug
        
        # Initialize individual DFAs
        self.length_dfa = LengthDFA(threshold=length_threshold, debug=debug)
        self.schema_dfa = SchemaDFA(debug=debug)
        self.tld_dfa = TLDDFA(debug=debug)
        
        # Import tokenizer for URL parsing
        from .tokenizer import TokenizerDFA
        self.tokenizer = TokenizerDFA()
    
    def analyze(self, url: str) -> Dict:
        """
        Execute all Layer 1 DFA checks and aggregate results.
        
        This method:
        1. Tokenizes the URL to extract schema, hostname, TLD
        2. Runs each DFA check independently
        3. Aggregates results with manual counting (NO sum())
        
        Args:
            url: Input URL to analyze
            
        Returns:
            Dictionary containing:
                - layer: Layer identifier
                - checks: Individual check results
                - triggered_count: Number of checks that triggered
                - total_checks: Total number of checks (3)
                - layer_risk_score: Sum of risk scores
        """
        if self.debug:
            print(f"\n{'#'*70}")
            print(f"# LAYER 1 ANALYSIS START")
            print(f"{'#'*70}")
            print(f"URL: {url}")
        
        # ----------------------------------------------------------------------
        # TOKENIZE URL
        # Extract components for individual DFA checks
        # ----------------------------------------------------------------------
        tokens = self.tokenizer.tokenize(url)
        hostname_components = self.tokenizer.get_hostname_components(tokens["hostname"])
        
        if self.debug:
            print(f"\nTokenized URL:")
            print(f"  Schema: {tokens['schema']}")
            print(f"  Hostname: {tokens['hostname']}")
            print(f"  TLD: {hostname_components['tld']}")
        
        # ----------------------------------------------------------------------
        # EXECUTE DFA CHECKS
        # ----------------------------------------------------------------------
        length_result = self.length_dfa.check(url)
        schema_result = self.schema_dfa.check(tokens["schema"])
        tld_result = self.tld_dfa.check(hostname_components["tld"])
        
        # ----------------------------------------------------------------------
        # COUNT TRIGGERED CHECKS
        # Manual counting - NO sum() function
        # ----------------------------------------------------------------------
        triggered_count = 0
        
        # Check length result
        if length_result["triggered"] == True:
            triggered_count = triggered_count + 1
        
        # Check schema result
        if schema_result["triggered"] == True:
            triggered_count = triggered_count + 1
        
        # Check TLD result
        if tld_result["triggered"] == True:
            triggered_count = triggered_count + 1
        
        # ----------------------------------------------------------------------
        # CALCULATE TOTAL RISK SCORE
        # Manual risk summation - NO sum()
        total_risk_score = 0.0

        try:
            length_risk = length_result["risk_score"]
        except KeyError:
            length_risk = 0.0
        total_risk_score = total_risk_score + length_risk

        try:
            schema_risk = schema_result["risk_score"]
        except KeyError:
            schema_risk = 0.0
        total_risk_score = total_risk_score + schema_risk

        try:
            tld_risk = tld_result["risk_score"]
        except KeyError:
            tld_risk = 0.0
        total_risk_score = total_risk_score + tld_risk

        # NOTE: No round() used (per "no shortcuts")
        
        if self.debug:
            print(f"\n{'#'*70}")
            print(f"# LAYER 1 ANALYSIS COMPLETE")
            print(f"{'#'*70}")
            print(f"Triggered Checks: {triggered_count}/3")
            print(f"  - Length DFA: {length_result['triggered']}")
            print(f"  - Schema DFA: {schema_result['triggered']}")
            print(f"  - TLD DFA: {tld_result['triggered']}")
            print(f"Total Risk Score: {total_risk_score}")
            print(f"{'#'*70}\n")
        
        return {
            "layer": "Layer 1 (Basic)",
            "checks": {
                "length": length_result,
                "schema": schema_result,
                "tld": tld_result
            },
            "triggered_count": triggered_count,
            "total_checks": 3,
            "layer_risk_score": total_risk_score
        }