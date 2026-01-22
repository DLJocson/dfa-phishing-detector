# ---------------------------------------------------------------------------
# COMPONENT: RiskScorer
# DESCRIPTION: Combines DFA layer outputs into weighted risk scores and levels.
# ---------------------------------------------------------------------------

"""
Formal Definition: RiskScorer is not a DFA, but a scoring/classification aggregator.
    - Input: List of DFA layer results (dicts with triggered checks and scores)
    - Output: Risk score (float), risk level (enum), color, and breakdown
    - Uses weighted sum of triggered DFA checks across layers
    - Thresholds define risk levels: Benign, Low, Medium, High, Critical
"""

from typing import Dict, List, Tuple
from enum import Enum


class RiskLevel(Enum):
    """Risk classification levels for phishing detection results."""
    BENIGN = "Benign"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class RiskScorer:
    """
    Weighted risk scoring and classification system.
    Aggregates DFA layer outputs, applies weights, and classifies risk.
    
    Formal Definition: Not a DFA - mathematical scoring function
    Input: Layer results L = {l1, l2, l3} where each li contains triggered checks
    Output: Risk score S ∈ [0, max_score] and risk level R ∈ {Benign, Low, Medium, High, Critical}
    """

    def __init__(self):
        # Global layer multipliers (stratified weighting)
        # A single high-layer "Critical" finding should outweigh multiple low-layer minor findings.
        self.layer_multipliers = {
            "Layer 1 (Basic)": 1.0,     # Structural Sieve
            "Layer 2 (Advanced)": 2.5,  # Analytical Core
            "Layer 3 (Threat)": 5.0     # Behavioral Analyst
        }
        
        # Theoretical maximum score calculation (all checks triggered with max base weights)
        # Layer 1: length(1.0) + schema(1.0) + tld(1.0) + lexical(1.0) = 4.0 base → 4.0 × 1.0 = 4.0
        # Layer 2: homograph(2.0) + depth(1.0) + keyword(1.2) + punycode(1.5) = 5.7 base → 5.7 × 2.5 = 14.25
        # Layer 3: chained(3.0) + dynamic(1.5) + redirect(1.8) = 6.3 base → 6.3 × 5.0 = 31.5
        # Total max: 4.0 + 14.25 + 31.5 = 49.75 → rounded up for UI clarity
        self.max_score = 50.0

        # Human-readable transparency payload for frontend display
        # These weights are the "base" per-check scores emitted by each layer DFA.
        self.weight_transparency = {
            "layer_multipliers": {
                "Layer 1 (Basic)": {
                    "role": "Structural Sieve",
                    "multiplier": 1.0,
                    "justification": "Identifies protocol-level anomalies and 'junk' traffic (higher false-positive potential for long URLs)."
                },
                "Layer 2 (Advanced)": {
                    "role": "Analytical Core",
                    "multiplier": 2.5,
                    "justification": "Focuses on active deception (Homographs, deep nesting) which are higher-intent indicators than simple length."
                },
                "Layer 3 (Threat)": {
                    "role": "Behavioral Analyst",
                    "multiplier": 5.0,
                    "justification": "Interrogates functional intent (Open Redirects, DGA) representing sophisticated 'living off the land' threats."
                }
            },
            "check_base_weights": {
                # Layer 1 (Schema) — critical hosting-less/local exploitation attempts
                "Layer 1 (Basic)": {
                    "schema:data": {"base_weight": 1.0, "severity": "Critical", "justification": "Hosting-less/local exploitation attempt; no legitimate external use case."},
                    "schema:file": {"base_weight": 1.0, "severity": "Critical", "justification": "Local file scheme; no legitimate external use case in normal browsing."},
                },
                # Layer 2 (Homograph)
                "Layer 2 (Advanced)": {
                    "homograph": {"base_weight": 2.0, "severity": "Critical", "justification": "Definitive indicator of brand impersonation via lookalike characters."},
                },
                # Layer 3 (Chained)
                "Layer 3 (Threat)": {
                    "chained": {"base_weight": 2.0, "severity": "Critical", "justification": "Redirect chains indicate high-severity intent; weighted by Layer 3 multiplier."},
                }
            }
        }
        
        self.risk_thresholds = [
            (RiskLevel.CRITICAL, 20.0), # Hit if L3 Chained + L2 Homograph
            (RiskLevel.HIGH, 10.0),     # Hit if L3 Chained alone or strong L2
            (RiskLevel.MEDIUM, 4.0),    # Hit if multiple L1/L2 issues
            (RiskLevel.LOW, 0.5),       # Any minor trigger
        ]

    def calculate_score(self, layer_results: List[Dict]) -> Tuple[float, Dict]:
        """Calculate weighted risk score from hierarchical layer results"""
        total_score = 0.0
        breakdown = {
            "raw_layer_scores": {},
            "weighted_layer_scores": {},
            # Backward/legacy alias used by some frontend components
            "layer_scores": {},
            "check_details": []
        }
        
        for layer_result in layer_results:
            layer_name = layer_result.get("layer", "Unknown")
            
            multiplier = self.layer_multipliers.get(layer_name, 1.0)
            raw_layer_score = layer_result.get("layer_risk_score", 0.0)
            weighted_score = raw_layer_score * multiplier
            
            total_score += weighted_score
            breakdown["raw_layer_scores"][layer_name] = round(raw_layer_score, 2)
            breakdown["weighted_layer_scores"][layer_name] = round(weighted_score, 2)
            breakdown["layer_scores"][layer_name] = round(weighted_score, 2)
            
            # Diagnostic details
            # Calculate contribution: base_weight × layer_multiplier
            # Example: keyword base=1.20, Layer 2 multiplier=2.5 → contribution = 1.20 × 2.5 = 3.00
            checks = layer_result.get("checks", {})
            for check_name, check_result in checks.items():
                if check_result.get("triggered", False):
                    raw_score = check_result.get("risk_score", 0.0)
                    contribution = raw_score * multiplier
                    
                    breakdown["check_details"].append({
                        "layer": layer_name,
                        "check": check_name,
                        "raw_score": raw_score,
                        "multiplier": multiplier,
                        "contribution": round(contribution, 2),
                        "reason": check_result.get("reason", "Unknown")
                    })
        
        return round(total_score, 2), breakdown
    
    def classify(self, score: float) -> RiskLevel:
        """Classify risk level based on weighted score"""
        for risk_level, threshold in self.risk_thresholds:
            if score >= threshold:
                return risk_level
        return RiskLevel.BENIGN
    
    def get_risk_color(self, risk_level: RiskLevel) -> str:
        color_map = {
            RiskLevel.BENIGN: "#10b981",  # Green
            RiskLevel.LOW: "#3b82f6",     # Blue
            RiskLevel.MEDIUM: "#f59e0b",  # Amber
            RiskLevel.HIGH: "#ef4444",    # Red
            RiskLevel.CRITICAL: "#991b1b" # Dark Red
        }
        return color_map.get(risk_level, "#6b7280")
    
    def analyze(self, layer_results: List[Dict]) -> Dict:
        """Complete risk analysis"""
        score, breakdown = self.calculate_score(layer_results)
        risk_level = self.classify(score)

        # Calculate total checks and total triggered checks
        total_checks = 0
        total_triggered = 0
        for layer_result in layer_results:
            checks = layer_result.get("checks", {})
            total_checks += len(checks)
            total_triggered += sum(1 for check in checks.values() if check.get("triggered", False))
        
        return {
            "risk_score": score,
            "risk_level": risk_level.value,
            "risk_color": self.get_risk_color(risk_level),
            "breakdown": breakdown,
            "weights": self.weight_transparency,
            "max_score": self.max_score,
            "total_checks_triggered": total_triggered,
            "total_checks": total_checks 
        }