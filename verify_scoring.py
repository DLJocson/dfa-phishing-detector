#!/usr/bin/env python3
"""
Verify scoring consistency with the problematic URL
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

from backend.app.logic.tokenizer import TokenizerDFA
from backend.app.logic.layer1 import Layer1
from backend.app.logic.layer2 import Layer2
from backend.app.logic.layer3 import Layer3
from backend.app.models.risk_scorer import RiskScorer

def test_problematic_url():
    """Test the specific URL that showed inconsistencies"""
    
    # Initialize components
    tokenizer = TokenizerDFA()
    layer1 = Layer1()
    layer2 = Layer2()
    layer3 = Layer3()
    risk_scorer = RiskScorer()
    
    # The problematic URL from the image
    url = "javascript://xn--pple-43d.раура1.login.security-update.account.verify.important-update.example.xyz:8080/secure/paypal/login.php?session=1234567890&redirect=http://192.168.1.100/phis"
    
    print("=" * 80)
    print("TESTING PROBLEMATIC URL")
    print("=" * 80)
    print(f"URL: {url}")
    print()
    
    # Analyze with all layers
    layer1_result = layer1.analyze(url)
    layer2_result = layer2.analyze(url)
    layer3_result = layer3.analyze(url)
    all_layers = [layer1_result, layer2_result, layer3_result]
    
    # Calculate risk score
    risk_analysis = risk_scorer.analyze(all_layers)
    
    print("LAYER SCORES (from backend):")
    print(f"  Layer 1: {layer1_result['layer_risk_score']:.2f}")
    print(f"  Layer 2: {layer2_result['layer_risk_score']:.2f}")
    print(f"  Layer 3: {layer3_result['layer_risk_score']:.2f}")
    print()
    
    print("INDIVIDUAL CHECK SCORES:")
    for layer_result in all_layers:
        layer_name = layer_result['layer']
        print(f"\n{layer_name}:")
        for check_name, check_result in layer_result['checks'].items():
            if check_result.get('triggered', False):
                score = check_result.get('risk_score', 0.0)
                reason = check_result.get('reason', 'No reason')
                print(f"  {check_name}: {score:.2f} - {reason}")
    
    print(f"\nRISK ANALYSIS SUMMARY:")
    print(f"  Total Score: {risk_analysis['risk_score']:.2f}")
    print(f"  Risk Level: {risk_analysis['risk_level']}")
    print(f"  Max Score: {risk_analysis['max_score']:.2f}")
    print(f"  Checks Triggered: {risk_analysis['total_checks_triggered']}/{risk_analysis['total_checks']}")
    
    # Verify diagnostic details sum
    diagnostic_total = sum(detail['score'] for detail in risk_analysis['breakdown']['check_details'])
    print(f"\nDIAGNOSTIC VERIFICATION:")
    print(f"  Diagnostic Details Sum: {diagnostic_total:.2f}")
    print(f"  Backend Total Score: {risk_analysis['risk_score']:.2f}")
    print(f"  Match: {'✅ YES' if abs(diagnostic_total - risk_analysis['risk_score']) < 0.01 else '❌ NO'}")
    
    # Expected based on sample data
    print(f"\nEXPECTED vs ACTUAL COMPARISON:")
    print(f"  Expected Layer 1: 2.70, Actual: {layer1_result['layer_risk_score']:.2f}")
    print(f"  Expected Layer 2: 5.00, Actual: {layer2_result['layer_risk_score']:.2f}")
    print(f"  Expected Layer 3: 1.80, Actual: {layer3_result['layer_risk_score']:.2f}")
    print(f"  Expected Total: 9.50, Actual: {risk_analysis['risk_score']:.2f}")

if __name__ == "__main__":
    test_problematic_url()
