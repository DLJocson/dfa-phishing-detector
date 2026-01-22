#!/usr/bin/env python3
"""
Test script to verify scoring consistency between backend components
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

from backend.app.logic.tokenizer import TokenizerDFA
from backend.app.logic.layer1 import Layer1
from backend.app.logic.layer2 import Layer2
from backend.app.logic.layer3 import Layer3
from backend.app.models.risk_scorer import RiskScorer

def test_scoring_consistency():
    """Test scoring consistency with sample URLs"""
    
    # Initialize components
    tokenizer = TokenizerDFA()
    layer1 = Layer1()
    layer2 = Layer2()
    layer3 = Layer3()
    risk_scorer = RiskScorer()
    
    # Test URLs with different risk levels
    test_urls = [
        "https://google.com",  # Benign
        "http://example.com",  # Low risk (http schema)
        "https://very-long-subdomain-name.example.com/path/with/many/segments",  # Medium risk
        "https://xn--e1awd7f.xn--p1ai",  # High risk (punycode)
        "http://bit.ly/redirect?url=http://malicious.com",  # Critical risk
    ]
    
    print("=" * 80)
    print("SCORING CONSISTENCY TEST RESULTS")
    print("=" * 80)
    
    for i, url in enumerate(test_urls, 1):
        print(f"\nTest {i}: {url}")
        print("-" * 60)
        
        # Analyze with all layers
        layer1_result = layer1.analyze(url)
        layer2_result = layer2.analyze(url)
        layer3_result = layer3.analyze(url)
        all_layers = [layer1_result, layer2_result, layer3_result]
        
        # Calculate risk score
        risk_analysis = risk_scorer.analyze(all_layers)
        
        print(f"Layer Names:")
        print(f"  Layer 1: {layer1_result['layer']}")
        print(f"  Layer 2: {layer2_result['layer']}")
        print(f"  Layer 3: {layer3_result['layer']}")
        
        print(f"\nLayer Scores (from backend):")
        print(f"  Layer 1: {risk_analysis['breakdown']['layer_scores'].get('Layer 1 (Basic)', 0):.2f}")
        print(f"  Layer 2: {risk_analysis['breakdown']['layer_scores'].get('Layer 2 (Advanced)', 0):.2f}")
        print(f"  Layer 3: {risk_analysis['breakdown']['layer_scores'].get('Layer 3 (Threat)', 0):.2f}")
        
        print(f"\nRisk Analysis:")
        print(f"  Total Score: {risk_analysis['risk_score']:.2f}")
        print(f"  Risk Level: {risk_analysis['risk_level']}")
        print(f"  Max Score: {risk_analysis['max_score']:.2f}")
        print(f"  Checks Triggered: {risk_analysis['total_checks_triggered']}/{risk_analysis['total_checks']}")
        
        # Verify frontend compatibility
        frontend_max_score = risk_analysis['max_score']
        frontend_percentage = (risk_analysis['risk_score'] / frontend_max_score) * 100
        
        print(f"\nFrontend Compatibility:")
        print(f"  Gauge Percentage: {frontend_percentage:.1f}%")
        print(f"  Score Display: {risk_analysis['risk_score']:.2f} / {frontend_max_score:.2f}")

if __name__ == "__main__":
    test_scoring_consistency()
