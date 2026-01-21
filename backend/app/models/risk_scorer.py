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
            "homograph": 2.0,
            "depth": 1.2,
            "keyword": 1.2,
            "punycode": 1.8,
            "chained": 1.5,
            "dynamic": 1.0,
            "redirect": 1.3
        }
        
        self.risk_thresholds = {
            RiskLevel.BENIGN: 0.0,
            RiskLevel.LOW: 0.5,
            RiskLevel.MEDIUM: 2.0,
            RiskLevel.HIGH: 4.0,
            RiskLevel.CRITICAL: 6.0
        }
    
    def calculate_score(self, layer_results: List[Dict]) -> Tuple[float, Dict]:
        """Calculate weighted risk score from all layers"""
        total_score = 0.0
        breakdown = {"layer_scores": {}, "check_details": []}
        
        for layer_result in layer_results:
            layer_name = layer_result.get("layer", "Unknown")
            layer_weight = self.layer_weights.get(layer_name, 1.0)
            layer_score = 0.0
            
            checks = layer_result.get("checks", {})
            for check_name, check_result in checks.items():
                if check_result.get("triggered", False):
                    check_weight = self.check_weights.get(check_name, 1.0)
                    weighted_score = check_weight * layer_weight
                    layer_score += weighted_score
                    total_score += weighted_score
                    
                    breakdown["check_details"].append({
                        "layer": layer_name,
                        "check": check_name,
                        "weight": check_weight,
                        "layer_weight": layer_weight,
                        "score": weighted_score,
                        "reason": check_result.get("reason", "Unknown")
                    })
            
            breakdown["layer_scores"][layer_name] = layer_score
        
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
        
        return {
            "risk_score": round(score, 2),
            "risk_level": risk_level.value,
            "risk_color": self.get_risk_color(risk_level),
            "breakdown": breakdown,
            "total_checks_triggered": sum(layer.get("triggered_count", 0) for layer in layer_results),
            "total_checks": sum(layer.get("total_checks", 0) for layer in layer_results)
        }
