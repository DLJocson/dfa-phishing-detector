"""Risk Scoring & Classification: Combines DFA layer outputs into risk scores and levels"""

from typing import Dict, List, Tuple
from enum import Enum


class RiskLevel(Enum):
    """Risk classification levels"""
    BENIGN = "Benign"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class RiskScorer:
    """Weighted risk scoring and classification system"""
    
    def __init__(self):
        self.layer_weights = {
            "Layer 1 (Basic)": 1.0,
            "Layer 2 (Advanced)": 1.5,
            "Layer 3 (Threat)": 2.0
        }
        
        self.check_weights = {
            "length": 0.3,
            "schema": 0.8,
            "tld": 1.0,
            "lexical": 1.0,
            "homograph": 2.0,
            "depth": 1.2,
            "keyword": 1.2,
            "punycode": 1.8,
            "chained": 1.5,
            "dynamic": 1.0,
            "redirect": 1.3
        }
        
        # Calculate max possible score: sum of maximum individual check scores
        self.max_score = (
            # Layer 1 (Basic) - maximum possible scores
            1.0 +  # length (max 1.0 for buffer overflow)
            1.0 +  # schema (max 1.0 for malicious schemas)
            1.0 +  # tld (max 1.0 for high-risk TLD)
            1.0 +  # lexical (max 1.0)
            # Layer 2 (Advanced) - maximum possible scores
            1.5 +  # homograph (max 1.5)
            1.0 +  # depth (max 1.0)
            1.2 +  # keyword (max 1.2)
            1.3 +  # punycode (max 1.3)
            # Layer 3 (Threat) - maximum possible scores
            2.0 +  # chained (max 2.0)
            1.5 +  # dynamic (max 1.5)
            1.8    # redirect (max 1.8)
        )
        
        self.risk_thresholds = {
            RiskLevel.BENIGN: 0.0,
            RiskLevel.LOW: 2.0,
            RiskLevel.MEDIUM: 6.0,
            RiskLevel.HIGH: 12.0,
            RiskLevel.CRITICAL: self.max_score
        }
    
    def calculate_score(self, layer_results: List[Dict]) -> Tuple[float, Dict]:
        """Calculate risk score from layer results (use pre-calculated layer scores)"""
        total_score = 0.0
        breakdown = {"layer_scores": {}, "check_details": []}
        
        for layer_result in layer_results:
            layer_name = layer_result.get("layer", "Unknown")
            layer_score = layer_result.get("layer_risk_score", 0.0)
            
            # Use the layer's pre-calculated score directly
            total_score += layer_score
            breakdown["layer_scores"][layer_name] = layer_score
            
            # Add check details for diagnostic purposes
            checks = layer_result.get("checks", {})
            for check_name, check_result in checks.items():
                if check_result.get("triggered", False):
                    breakdown["check_details"].append({
                        "layer": layer_name,
                        "check": check_name,
                        "weight": check_result.get("risk_score", 0.0),
                        "layer_weight": 1.0,  # No additional weighting
                        "score": check_result.get("risk_score", 0.0),
                        "reason": check_result.get("reason", "Unknown")
                    })
        
        return total_score, breakdown
    
    def classify(self, score: float) -> RiskLevel:
        """Classify risk level based on score"""
        for risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
            if score >= self.risk_thresholds[risk_level]:
                return risk_level
        return RiskLevel.BENIGN
    
    def get_risk_color(self, risk_level: RiskLevel) -> str:
        """Get UI color code for risk level"""
        color_map = {
            RiskLevel.BENIGN: "#10b981",
            RiskLevel.LOW: "#3b82f6",
            RiskLevel.MEDIUM: "#f59e0b",
            RiskLevel.HIGH: "#ef4444",
            RiskLevel.CRITICAL: "#991b1b"
        }
        return color_map.get(risk_level, "#6b7280")
    
    def analyze(self, layer_results: List[Dict]) -> Dict:
        """Complete risk analysis with score, classification, and breakdown"""
        score, breakdown = self.calculate_score(layer_results)
        risk_level = self.classify(score)
        
        # Round layer scores to 2 decimal places to prevent floating-point precision issues
        for layer_name in breakdown["layer_scores"]:
            breakdown["layer_scores"][layer_name] = round(breakdown["layer_scores"][layer_name], 2)
        
        return {
            "risk_score": round(score, 2),
            "risk_level": risk_level.value,
            "risk_color": self.get_risk_color(risk_level),
            "max_score": round(self.max_score, 2),
            "breakdown": breakdown,
            "total_checks_triggered": sum(layer.get("triggered_count", 0) for layer in layer_results),
            "total_checks": sum(layer.get("total_checks", 0) for layer in layer_results)
        }
