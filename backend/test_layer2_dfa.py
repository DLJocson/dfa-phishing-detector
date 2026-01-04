#!/usr/bin/env python
"""
Layer 2 Advanced DFA Test Suite
================================

Tests formal state-transition table implementations for:
1. HomographDFA - Non-ASCII character detection
2. SubdomainDFA - Subdomain pattern analysis
3. PunycodeDFA - Punycode (xn--) prefix detection
"""

from app.logic.layer2 import Layer2, HomographDFA, SubdomainDFA, PunycodeDFA


def test_homograph_dfa():
    """Test HomographDFA with various hostnames"""
    print("\n" + "="*60)
    print("HOMOGRAPH DFA TESTS")
    print("="*60)
    
    dfa = HomographDFA()
    
    test_cases = [
        ("www.google.com", False, "ASCII-only hostname"),
        ("www.раypal.com", True, "Cyrillic 'а' (U+0430) instead of Latin 'a'"),
        ("www.αpple.com", True, "Greek alpha (U+03B1) instead of Latin 'a'"),
        ("www.example.com", False, "Safe ASCII hostname"),
    ]
    
    for hostname, expected_trigger, description in test_cases:
        result = dfa.check(hostname)
        status = "✓ PASS" if result["triggered"] == expected_trigger else "✗ FAIL"
        print(f"\n{status} - {description}")
        print(f"  Hostname: {hostname}")
        print(f"  Triggered: {result['triggered']}")
        print(f"  State: {result['state']}")
        print(f"  Risk Score: {result['risk_score']}")
        if result['triggered']:
            print(f"  Details: {result['details']}")


def test_subdomain_dfa():
    """Test SubdomainDFA with various hostnames"""
    print("\n" + "="*60)
    print("SUBDOMAIN DFA TESTS")
    print("="*60)
    
    dfa = SubdomainDFA(max_depth=4)
    
    test_cases = [
        ("www.google.com", False, "Normal 3-part domain"),
        ("mail.google.com", False, "Normal subdomain"),
        ("a.b.c.d.e.f.example.com", True, "Excessive depth (6 subdomains)"),
        ("paypal.com.attacker-site.net", True, "Brand jacking attack"),
        ("secure.login.verify.example.com", True, "Suspicious keywords in subdomain"),
        ("example.com", False, "Simple domain"),
    ]
    
    for hostname, expected_trigger, description in test_cases:
        result = dfa.check(hostname)
        status = "✓ PASS" if result["triggered"] == expected_trigger else "✗ FAIL"
        print(f"\n{status} - {description}")
        print(f"  Hostname: {hostname}")
        print(f"  Triggered: {result['triggered']}")
        print(f"  State: {result['state']}")
        print(f"  Risk Score: {result['risk_score']}")
        if result['details']:
            details = result['details']
            print(f"  Parts: {details.get('parts', [])}")
            print(f"  Subdomains: {details.get('num_subdomains', 0)}")
            if 'issues' in details and details['issues']:
                print(f"  Issues: {details['issues']}")


def test_punycode_dfa():
    """Test PunycodeDFA with various hostnames"""
    print("\n" + "="*60)
    print("PUNYCODE DFA TESTS")
    print("="*60)
    
    dfa = PunycodeDFA()
    
    test_cases = [
        ("www.google.com", False, "Normal ASCII domain"),
        ("xn--pple-43d.com", True, "Punycode apple variant"),
        ("www.xn--pple-43d.com", True, "Subdomain with Punycode"),
        ("xn--e1afmkfd.xn--p1ai.example.com", True, "Multiple Punycode parts"),
        ("example.com", False, "Safe ASCII domain"),
    ]
    
    for hostname, expected_trigger, description in test_cases:
        result = dfa.check(hostname)
        status = "✓ PASS" if result["triggered"] == expected_trigger else "✗ FAIL"
        print(f"\n{status} - {description}")
        print(f"  Hostname: {hostname}")
        print(f"  Triggered: {result['triggered']}")
        print(f"  State: {result['state']}")
        print(f"  Risk Score: {result['risk_score']}")
        if result['triggered']:
            print(f"  Details: {result['details']}")


def test_layer2_coordinator():
    """Test Layer2 coordinator with full URLs"""
    print("\n" + "="*60)
    print("LAYER 2 COORDINATOR TESTS")
    print("="*60)
    
    layer2 = Layer2()
    
    test_urls = [
        "https://www.google.com",
        "https://xn--pple-43d.com",
        "https://paypal.com.attacker-site.net",
        "https://a.b.c.d.e.f.example.com",
    ]
    
    for url in test_urls:
        print(f"\n{'='*40}")
        print(f"Testing URL: {url}")
        print(f"{'='*40}")
        
        try:
            result = layer2.analyze(url)
            print(f"Layer: {result['layer']}")
            print(f"Hostname: {result['hostname']}")
            print(f"Triggered Checks: {result['triggered_count']}/{result['total_checks']}")
            print(f"Layer Risk Score: {result['layer_risk_score']}")
            
            print("\nIndividual Check Results:")
            for check_name, check_result in result['checks'].items():
                status = "TRIGGERED" if check_result['triggered'] else "SAFE"
                print(f"  {check_name.upper()}: {status} (risk: {check_result['risk_score']})")
        except Exception as e:
            print(f"Error analyzing URL: {e}")


if __name__ == "__main__":
    print("\n" + "█"*60)
    print("█ LAYER 2 - ADVANCED DFA TEST SUITE")
    print("█"*60)
    
    test_homograph_dfa()
    test_subdomain_dfa()
    test_punycode_dfa()
    test_layer2_coordinator()
    
    print("\n" + "█"*60)
    print("█ TEST SUITE COMPLETE")
    print("█"*60 + "\n")
