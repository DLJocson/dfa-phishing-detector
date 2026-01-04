#!/usr/bin/env python3
"""Test script for Layer 1 DFA implementation"""

import sys
sys.path.insert(0, '.')

from app.logic.layer1 import Layer1

# Test cases
test_urls = [
    "https://www.google.com",                              # Safe
    "https://www.paypal.com.secure-login.tk",             # High risk TLD
    "file://malicious-script.exe",                         # Suspicious schema
    "https://www.example.com/very/long/path/with/many/segments/that/exceed/the/normal/threshold/for/phishing/obfuscation",  # Long URL
]

layer1 = Layer1()

print("="*70)
print("LAYER 1 DFA TEST RESULTS")
print("="*70)

for i, url in enumerate(test_urls, 1):
    print(f"\nTest {i}: {url[:50]}..." if len(url) > 50 else f"\nTest {i}: {url}")
    print("-" * 70)
    
    result = layer1.analyze(url)
    
    print(f"Triggered Checks: {result['triggered_count']}/{result['total_checks']}")
    print(f"Layer Risk Score: {result['layer_risk_score']}")
    
    for check_name, check_result in result['checks'].items():
        state = check_result.get('state', 'UNKNOWN')
        triggered = check_result.get('triggered', False)
        reason = check_result.get('reason', 'N/A')
        risk_score = check_result.get('risk_score', 0.0)
        
        status = "✓ PASS" if not triggered else "✗ TRIGGERED"
        print(f"\n  {check_name.upper()}:")
        print(f"    State: {state}")
        print(f"    Status: {status}")
        print(f"    Reason: {reason}")
        print(f"    Risk Score: {risk_score}")

print("\n" + "="*70)
print("TEST COMPLETE")
print("="*70)
