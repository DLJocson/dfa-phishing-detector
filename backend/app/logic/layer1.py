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

# ------------------------------------------------------------------------------
# 1. LengthDFA
# ------------------------------------------------------------------------------
#this dfa checks for length of the url
#if the url exceeds 75 character threshold, it triggers
class LengthDFA:
    """
    Formal Definition: M = (Q, Σ, δ, q₀, F)
        Q = {START, UNDER_THRESHOLD, SUSPICIOUS_LENGTH, BUFFER_OVERFLOW, RFC_VIOLATION, REJECT}
        Σ = {char | char ∈ printable ASCII [32-126]}
        δ: Q × Σ × N → Q (state, symbol, count)
        q₀ = START
        F = {SUSPICIOUS_LENGTH, BUFFER_OVERFLOW, RFC_VIOLATION}
    """

    START = "START"
    UNDER_THRESHOLD = "UNDER_THRESHOLD"
    SUSPICIOUS_LENGTH = "SUSPICIOUS_LENGTH"
    BUFFER_OVERFLOW = "BUFFER_OVERFLOW"
    RFC_VIOLATION = "RFC_VIOLATION"
    REJECT = "REJECT"

    def __init__(self, threshold: int = 75, debug: bool = False):
        self.suspicious_threshold = threshold
        self.overflow_threshold = 2048
        self.rfc_limit = 8000
        self.debug = debug
        self._accepting_states = {self.SUSPICIOUS_LENGTH, self.BUFFER_OVERFLOW, self.RFC_VIOLATION}

    def _classify_char(self, char: str) -> str:
        return "char"

    def _transition(self, state: str, symbol: str, count: int) -> str:
        if count > self.rfc_limit:
            return self.RFC_VIOLATION

        if state == self.START:
            return self.UNDER_THRESHOLD

        if state == self.UNDER_THRESHOLD:
            if count > self.overflow_threshold:
                return self.BUFFER_OVERFLOW
            if count > self.suspicious_threshold:
                return self.SUSPICIOUS_LENGTH
            return self.UNDER_THRESHOLD

        if state == self.SUSPICIOUS_LENGTH:
            if count > self.overflow_threshold:
                return self.BUFFER_OVERFLOW
            return self.SUSPICIOUS_LENGTH

        if state == self.BUFFER_OVERFLOW:
            return self.BUFFER_OVERFLOW

        return self.REJECT

    def check(self, url: str) -> Dict:
        if not url:
            return {
                "triggered": False,
                "state": self.REJECT,
                "reason": "Empty URL",
                "value": 0,
                "threshold": self.suspicious_threshold,
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
                    "threshold": self.suspicious_threshold,
                    "risk_score": 0.0,
                }

            char_count += 1
            current_state = self._transition(current_state, symbol, char_count)

            if current_state == self.SUSPICIOUS_LENGTH:
                pass
            if current_state == self.BUFFER_OVERFLOW:
                break
            if current_state == self.RFC_VIOLATION:
                break

        triggered = current_state in self._accepting_states

        risk_score = 0.0
        reason = "Length acceptable"
        
        if current_state == self.SUSPICIOUS_LENGTH:
            risk_score = 0.3
            reason = f"Length ({char_count}) > {self.suspicious_threshold}"
        elif current_state == self.BUFFER_OVERFLOW:
            risk_score = 1.0 
            reason = f"Buffer Overflow Risk: ({char_count} > {self.overflow_threshold})"
        elif current_state == self.RFC_VIOLATION:
            risk_score = 1.0 
            reason = f"RFC Violation / DoS Risk: ({char_count} > {self.rfc_limit})"

        return {
            "triggered": triggered,
            "state": current_state,
            "reason": reason,
            "value": char_count,
            "risk_score": risk_score,
        }

# ------------------------------------------------------------------------------
# 2. SchemaDFA
# ------------------------------------------------------------------------------

#this DFA checks for malicious schemas like data: and file: and 
#keeps schemas such as http: and https: as safe
class SchemaDFA:
    """
    Formal Definition: M = (Q, Σ, δ, q₀, F)
        Q = {START, H, HT, HTT, HTTP, HTTPS, INSECURE_HTTP, NEUTRAL_HTTPS,
             F, FI, FIL, FILE, MALICIOUS_FILE, FT, FTP, MALICIOUS_FTP,
             D, DA, DAT, DATA, MALICIOUS_DATA, B, BL, BLO, BLOB, MALICIOUS_DYNAMIC,
             J, JA, JAV, JAVA, JAVAS, JAVASC, JAVASCR, JAVASCRI, JAVASCRIP, JAVASCRIPT, MALICIOUS_SCRIPT,
             S, SM, SMS, SUSPICIOUS_APP, T, TE, TEL, TO, TOP, TF, TFT, TFTP, MALICIOUS_TFTP, REJECT}
        Σ = {a-z, A-Z, 0-9, ':', and URL-safe special chars}
        δ: Q × Σ → Q
        q₀ = START
        F = {MALICIOUS_DATA, MALICIOUS_FILE, MALICIOUS_SCRIPT, MALICIOUS_DYNAMIC, SUSPICIOUS_APP, INSECURE_HTTP, NEUTRAL_HTTPS}
    """
    def __init__(self, debug: bool = False):
        self.debug = debug

        # Base States
        self.START = "START"
        self.REJECT = "REJECT"
        
        # HTTP/HTTPS states
        self.H = "H"
        self.HT = "HT"
        self.HTT = "HTT"
        self.HTTP = "HTTP"
        self.HTTPS = "HTTPS"
        self.INSECURE_HTTP = "INSECURE_HTTP"    # Final state for http:
        self.NEUTRAL_HTTPS = "NEUTRAL_HTTPS"    # Final state for https:
        
        # FILE States
        self.F = "F"
        self.FI = "FI"
        self.FIL = "FIL"
        self.FILE = "FILE"
        self.MALICIOUS_FILE = "MALICIOUS_FILE"  # Final state for file:
        
        # DATA States
        self.D = "D"
        self.DA = "DA"
        self.DAT = "DAT"
        self.DATA = "DATA"
        self.MALICIOUS_DATA = "MALICIOUS_DATA" # Final state for data:
        
        # BLOB States
        self.B = "B"
        self.BL = "BL"
        self.BLO = "BLO"
        self.BLOB = "BLOB"
        self.MALICIOUS_DYNAMIC = "MALICIOUS_DYNAMIC" # Final state for blob:
        
        # JAVASCRIPT States (New)
        self.J = "J"
        self.JA = "JA"
        self.JAV = "JAV"
        self.JAVA = "JAVA"
        self.JAVAS = "JAVAS"
        self.JAVASC = "JAVASC"
        self.JAVASCR = "JAVASCR"
        self.JAVASCRI = "JAVASCRI"
        self.JAVASCRIP = "JAVASCRIP"
        self.JAVASCRIPT = "JAVASCRIPT"
        self.MALICIOUS_SCRIPT = "MALICIOUS_SCRIPT" # Final state for javascript:
        
        # SMS States
        self.S = "S"
        self.SM = "SM"
        self.SMS = "SMS"
        # Shared final state for SMS/TEL
        self.SUSPICIOUS_APP = "SUSPICIOUS_APP"
        
        # TEL States - Note: T overlaps with START->T in original, but here we define path
        self.T = "T"
        self.TE = "TE"
        self.TEL = "TEL"
        
        # FTP/TFTP states
        self.T = "T"
        self.TF = "TF"
        self.TFT = "TFT"
        self.TFTP = "TFTP"
        self.F = "F"
        self.FT = "FT"
        self.FTP = "FTP"
        self.MALICIOUS_FTP = "MALICIOUS_FTP"
        self.MALICIOUS_TFTP = "MALICIOUS_TFTP"
        
        self.trap_states = {
            self.MALICIOUS_DATA, self.MALICIOUS_FILE, self.MALICIOUS_SCRIPT,
            self.MALICIOUS_DYNAMIC, self.SUSPICIOUS_APP, self.MALICIOUS_FTP,
            self.MALICIOUS_TFTP
        }

        self._transition_table = {
            # Start branching
            (self.START, 'h'): self.H, (self.START, 'H'): self.H,
            (self.START, 'f'): self.F, (self.START, 'F'): self.F,
            (self.START, 'd'): self.D, (self.START, 'D'): self.D,
            (self.START, 'b'): self.B, (self.START, 'B'): self.B,
            (self.START, 'j'): self.J, (self.START, 'J'): self.J,
            (self.START, 's'): self.S, (self.START, 'S'): self.S,
            (self.START, 't'): self.T, (self.START, 'T'): self.T,

            # http/https
            (self.H, 't'): self.HT, (self.H, 'T'): self.HT,
            (self.HT, 't'): self.HTT, (self.HT, 'T'): self.HTT,
            (self.HTT, 'p'): self.HTTP, (self.HTT, 'P'): self.HTTP,
            (self.HTTP, 's'): self.HTTPS, (self.HTTP, 'S'): self.HTTPS,
            (self.HTTP, ':'): self.INSECURE_HTTP,
            (self.HTTPS, ':'): self.NEUTRAL_HTTPS,
        
            # tftp
            (self.T, 'f'): self.TF, (self.T, 'F'): self.TF,
            (self.T, 'F'): self.TF, (self.T, 'f'): self.TF,
            (self.TF, 't'): self.TFT, (self.TF, 'T'): self.TFT,
            (self.TFT, 'p'): self.TFTP, (self.TFT, 'P'): self.TFTP,
            (self.TFTP, ':'): self.MALICIOUS_TFTP,

            # data
            (self.D, 'a'): self.DA, (self.D, 'A'): self.DA,
            (self.DA, 't'): self.DAT, (self.DA, 'T'): self.DAT,
            (self.DAT, 'a'): self.DATA, (self.DAT, 'A'): self.DATA,
            (self.DATA, ':'): self.MALICIOUS_DATA,

            # file
            (self.F, 'i'): self.FI, (self.F, 'I'): self.FI,
            (self.FI, 'l'): self.FIL, (self.FI, 'L'): self.FIL,
            (self.FIL, 'e'): self.FILE, (self.FIL, 'E'): self.FILE,
            (self.FILE, ':'): self.MALICIOUS_FILE,

            # ftp
            (self.F, 't'): self.FT, (self.F, 'T'): self.FT,
            (self.FT, 'p'): self.FTP, (self.FT, 'P'): self.FTP,
            (self.FTP, ':'): self.MALICIOUS_FTP,
            
            # blob
            (self.B, 'l'): self.BL, (self.B, 'L'): self.BL,
            (self.BL, 'o'): self.BLO, (self.BL, 'O'): self.BLO,
            (self.BLO, 'b'): self.BLOB, (self.BLO, 'B'): self.BLOB,
            (self.BLOB, ':'): self.MALICIOUS_DYNAMIC,
            
            # javascript
            (self.J, 'a'): self.JA, (self.J, 'A'): self.JA,
            (self.JA, 'v'): self.JAV, (self.JA, 'V'): self.JAV,
            (self.JAV, 'a'): self.JAVA, (self.JAV, 'A'): self.JAVA,
            (self.JAVA, 's'): self.JAVAS, (self.JAVA, 'S'): self.JAVAS,
            (self.JAVAS, 'c'): self.JAVASC, (self.JAVAS, 'C'): self.JAVASC,
            (self.JAVASC, 'r'): self.JAVASCR, (self.JAVASC, 'R'): self.JAVASCR,
            (self.JAVASCR, 'i'): self.JAVASCRI, (self.JAVASCR, 'I'): self.JAVASCRI,
            (self.JAVASCRI, 'p'): self.JAVASCRIP, (self.JAVASCRI, 'P'): self.JAVASCRIP,
            (self.JAVASCRIP, 't'): self.JAVASCRIPT, (self.JAVASCRIP, 'T'): self.JAVASCRIPT,
            (self.JAVASCRIPT, ':'): self.MALICIOUS_SCRIPT,
            
            # sms
            (self.S, 'm'): self.SM, (self.S, 'M'): self.SM,
            (self.SM, 's'): self.SMS, (self.SM, 'S'): self.SMS,
            (self.SMS, ':'): self.SUSPICIOUS_APP,
            
            # tel
            (self.T, 'e'): self.TE, (self.T, 'E'): self.TE,
            (self.TE, 'l'): self.TEL, (self.TE, 'L'): self.TEL,
            (self.TEL, ':'): self.SUSPICIOUS_APP,
        }
        self.initial_state = self.START

    def check(self, schema: str) -> Dict:
        if not schema:
             return {"triggered": False, "state": self.REJECT, "risk_score": 0.0, "reason": "No Schema"}

        current_state = self.initial_state
        
        for char in schema:
            # If we are already in a confirmed malicious state, stop processing and accept.
            if current_state in self.trap_states:
                break

            current_state = self._transition_table.get((current_state, char), self.REJECT)
            if current_state == self.REJECT:
                break

        # If the string ended at "HTTPS" (without a colon), we map it to NEUTRAL_HTTPS.
        if current_state == self.HTTPS:
            current_state = self.NEUTRAL_HTTPS
        elif current_state == self.HTTP:
            current_state = self.INSECURE_HTTP
        elif current_state == self.DATA:
            current_state = self.MALICIOUS_DATA
        elif current_state == self.FILE:
            current_state = self.MALICIOUS_FILE
        elif current_state == self.JAVASCRIPT:
            current_state = self.MALICIOUS_SCRIPT
        elif current_state == self.BLOB:
            current_state = self.MALICIOUS_DYNAMIC
        elif current_state == self.SMS or current_state == self.TEL:
            current_state = self.SUSPICIOUS_APP
        elif current_state == self.FTP:
             current_state = self.MALICIOUS_FTP
        elif current_state == self.TFTP:
             current_state = self.MALICIOUS_TFTP

        triggered = True
        risk_score = 0.0
        reason = "Unknown Schema"

        if current_state == self.MALICIOUS_DATA:
            risk_score = 0.8
            reason = "Critical: 'data:' schema detected"
        elif current_state == self.MALICIOUS_FILE:
            risk_score = 1.0
            reason = "Critical: 'file:' schema detected"
        elif current_state == self.MALICIOUS_SCRIPT:
            risk_score = 1.0
            reason = "Critical: 'javascript:' schema detected"
        elif current_state == self.MALICIOUS_DYNAMIC:
            risk_score = 0.9
            reason = "High: 'blob:' schema detected"
        elif current_state == self.SUSPICIOUS_APP:
            risk_score = 0.6
            reason = "Suspicious: App schema (sms/tel) detected"
        elif current_state == self.INSECURE_HTTP:
            risk_score = 0.5
            reason = "Insecure: 'http:' schema detected"
        elif current_state == self.MALICIOUS_FTP or current_state == self.MALICIOUS_TFTP:
            risk_score = 0.7
            reason = "Risky: FTP/TFTP schema detected"
        elif current_state == self.NEUTRAL_HTTPS:
            risk_score = 0.0
            triggered = False
            reason = "Neutral: 'https:' schema"
        else:
            triggered = False
            reason = "Invalid/Unknown Schema"

        return {
            "triggered": triggered,
            "state": current_state,
            "reason": reason,
            "risk_score": risk_score,
            "value": schema
        }

# ------------------------------------------------------------------------------
# 3. TLDDFA
# ------------------------------------------------------------------------------
# this dfa detects suspicious tlds such as .zip, .exe, .mov, .tk, .xyz
class TLDDFA:
    """
    Formal Definition: M = (Q, Σ, δ, q₀, F)
        Q = {START, Z, ZI, ZIP, E, EX, EXE, M, MO, MOV, T, TK, TO, TOP, X, XY, XYZ, R, RU, C, CN, S, SU, MALICIOUS, REJECT}
        Σ = {a-z, A-Z, '.'}
        δ: Q × Σ → Q
        q₀ = START
        F = {ZIP, EXE, MOV, TK, XYZ, RU, CN, SU, TOP}
    """

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.START = "START"
        self.MALICIOUS = "MALICIOUS"
        self.REJECT = "REJECT"

        # States
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
        
        self.R = "R"
        self.RU = "RU"
        
        self.C = "C"
        self.CN = "CN"
        
        self.S = "S"
        self.SU = "SU"
        
        self.TO = "TO"
        self.TOP = "TOP"
        
        self.G = "G"
        self.GQ = "GQ"
        
        self.W = "W"
        self.WI = "WI"
        self.WIN = "WIN"
        
        self.B = "B"
        self.BO = "BO"
        self.BOT = "BOT"

        self._transition_table = {
            # Start Branching
            (self.START, 'z'): self.Z, (self.START, 'Z'): self.Z,
            (self.START, 'e'): self.E, (self.START, 'E'): self.E,
            (self.START, 'm'): self.M, (self.START, 'M'): self.M,
            (self.START, 't'): self.T, (self.START, 'T'): self.T,
            (self.START, 'x'): self.X, (self.START, 'X'): self.X,
            (self.START, 'r'): self.R, (self.START, 'R'): self.R,
            (self.START, 'c'): self.C, (self.START, 'C'): self.C,
            (self.START, 's'): self.S, (self.START, 'S'): self.S,
            (self.START, 'g'): self.G, (self.START, 'G'): self.G,
            (self.START, 'w'): self.W, (self.START, 'W'): self.W,
            (self.START, 'b'): self.B, (self.START, 'B'): self.B,
            
            # zip
            (self.START, '.'): self.START,
            (self.Z, 'i'): self.ZI, (self.Z, 'I'): self.ZI,
            (self.ZI, 'p'): self.ZIP, (self.ZI, 'P'): self.ZIP,
            
            # exe
            (self.E, 'x'): self.EX, (self.E, 'X'): self.EX, 
            (self.EX, 'e'): self.EXE, (self.EX, 'E'): self.EXE,
            
            # mov
            (self.M, 'o'): self.MO, (self.M, 'O'): self.MO,
            (self.MO, 'v'): self.MOV, (self.MO, 'V'): self.MOV,
            
            # tk
            (self.T, 'k'): self.TK, (self.T, 'K'): self.TK,
            (self.T, 'o'): self.TO, (self.T, 'O'): self.TO, # New branch
            (self.TO, 'p'): self.TOP, (self.TO, 'P'): self.TOP,
            
            # xyz
            (self.X, 'y'): self.XY, (self.X, 'Y'): self.XY,
            (self.XY, 'z'): self.XYZ, (self.XY, 'Z'): self.XYZ,
            
            # ru
            (self.R, 'u'): self.RU, (self.R, 'U'): self.RU,
            
            # cn
            (self.C, 'n'): self.CN, (self.C, 'N'): self.CN,
            
            # su
            (self.S, 'u'): self.SU, (self.S, 'U'): self.SU,
            
            # gq
            (self.G, 'q'): self.GQ, (self.G, 'Q'): self.GQ,

            # win
            (self.W, 'i'): self.WI, (self.W, 'I'): self.WI,
            (self.WI, 'n'): self.WIN, (self.WI, 'N'): self.WIN,

            # bot
            (self.B, 'o'): self.BO, (self.B, 'O'): self.BO,
            (self.BO, 't'): self.BOT, (self.BO, 'T'): self.BOT,
        }

        self._accepting_states = {
            self.ZIP, self.EXE, self.MOV, self.TK, self.XYZ,
            self.RU, self.CN, self.SU, self.TOP,
            self.GQ, self.WIN, self.BOT
        }

    def check(self, tld: str) -> Dict:
        if not tld:
            return {"triggered": False, "state": self.REJECT, "risk_score": 0.0, "reason": "No TLD"}

        current_state = self.START
        clean_tld = ""

        for char in tld:
            if char == '.' and current_state == self.START: continue
            clean_tld += char
            current_state = self._transition_table.get((current_state, char), self.REJECT)
            if current_state == self.REJECT: break
        
        triggered = current_state in self._accepting_states
        
        return {
            "triggered": triggered,
            "state": current_state if triggered else self.REJECT,
            "reason": f"High-risk TLD: .{clean_tld}" if triggered else "TLD acceptable",
            "value": clean_tld,
            "risk_score": 1.0 if triggered else 0.0
        }

# ------------------------------------------------------------------------------
# 4. Lexical & IP Feature Extractor (New Component)
# ------------------------------------------------------------------------------
# This component extracts lexical features from the hostname,
# such as counting dots and hyphens, and checks if the hostname is an IP address
class LexicalAnalyzer:
    def check_is_ip(self, hostname: str) -> bool:
        if not hostname: return False
        
        allowed = set("0123456789.")
        for char in hostname:
            if char not in allowed:
                return False
        return True

    def analyze(self, hostname: str) -> Dict:
        dot_count = hostname.count('.')
        hyphen_count = hostname.count('-')
        is_ip = self.check_is_ip(hostname)

        triggered = False
        risk = 0.0
        reasons = []

        if is_ip:
            triggered = True
            risk += 0.8
            reasons.append("Hostname is an IP Address")

        if dot_count > 3:
            triggered = True
            risk += 0.2
            reasons.append(f"High subdomain depth (dots={dot_count})")
        
        if hyphen_count > 2:
            triggered = True
            risk += 0.2
            reasons.append(f"High hyphen count ({hyphen_count})")

        return {
            "triggered": triggered,
            "risk_score": min(risk, 1.0),
            "reason": "; ".join(reasons) if reasons else "Lexical OK",
            "details": {"is_ip": is_ip, "dots": dot_count, "hyphens": hyphen_count}
        }


# ------------------------------------------------------------------------------
# LAYER 1 COORDINATOR
# Purpose: Orchestrate all Layer 1 DFA checks and aggregate results
# 
# This class combines:
#   1. LengthDFA - URL length anomaly detection
#   2. SchemaDFA - Malicious protocol detection  
#   3. TLDDFA - High-risk TLD detection
# ------------------------------------------------------------------------------

class Layer1:
    def __init__(self, length_threshold: int = 75, debug: bool = False):
        self.debug = debug
        
        # Initialize individual DFAs
        self.length_dfa = LengthDFA(threshold=length_threshold, debug=debug)
        self.schema_dfa = SchemaDFA(debug=debug)
        self.tld_dfa = TLDDFA(debug=debug)
        self.lexical_analyzer = LexicalAnalyzer()
        
        # Import tokenizer for URL parsing
        from .tokenizer import TokenizerDFA
        self.tokenizer = TokenizerDFA()
    
    def analyze(self, url: str) -> Dict:
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
        hostname_raw = tokens["hostname"]
        if ']' not in hostname_raw:
             hostname_clean = hostname_raw.split(':')[0] if ':' in hostname_raw else hostname_raw
        else:
             hostname_clean = hostname_raw 
        
        hostname_components = self.tokenizer.get_hostname_components(hostname_clean)
        
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
        tld_candidate = hostname_components.get("tld", "").lower()
        tld_result = self.tld_dfa.check(tld_candidate)
        lexical_result = self.lexical_analyzer.analyze(tokens["hostname"])
        
        # Userinfo Bypass Logic (.zip/.mov + @)
        is_risky_tld = tld_result["value"] in ["zip", "mov"]
        has_at_symbol = "@" in url
        
        if is_risky_tld and has_at_symbol:
            # Overwrite TLD result to Critical
            tld_result["triggered"] = True
            tld_result["risk_score"] = 1.0
            tld_result["reason"] = "CRITICAL: Namespace Collision Bypass (.zip/.mov + @)"
        
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
            
        # Check lexical result
        if lexical_result["triggered"] == True:
            triggered_count = triggered_count + 1
        
        # ----------------------------------------------------------------------
        # CALCULATE TOTAL RISK SCORE
        # ----------------------------------------------------------------------
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
        
        try:
            lexical_risk = lexical_result["risk_score"]
        except KeyError:
            lexical_risk = 0.0
        total_risk_score = total_risk_score + lexical_risk
        
        normalized_score = min(total_risk_score, 1.0)
        
        if self.debug:
            print(f"\n{'#'*70}")
            print(f"# LAYER 1 ANALYSIS COMPLETE")
            print(f"{'#'*70}")
            print(f"Triggered Checks: {triggered_count}/4")
            print(f"  - Length DFA: {length_result['triggered']}")
            print(f"  - Schema DFA: {schema_result['triggered']}")
            print(f"  - TLD DFA: {tld_result['triggered']}")
            print(f"  - Lexical & IP Feature Extractor: {lexical_result['triggered']}")
            print(f"Total Risk Score: {total_risk_score}")
            print(f"{'#'*70}\n")
        
        return {
            "layer": "Layer 1 (Basic)",
            "checks": {
                "length": length_result,
                "schema": schema_result,
                "tld": tld_result,
                "lexical": lexical_result
            },
            "triggered_count": triggered_count,
            "total_checks": 4,
            "layer_risk_score": round(total_risk_score, 2)
        }