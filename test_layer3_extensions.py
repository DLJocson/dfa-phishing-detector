"""
Test script for Layer 3 DFA extensions
Demonstrates all 5 new DFA detectors in action
"""

import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from app.logic.layer3 import (
    EncodedProtocolDFA,
    FragmentRedirectDFA,
    ShortenerDFA,
    CredentialPathDFA,
    SuspiciousTLDDFA,
    Layer3
)


def test_encoded_protocol_dfa():
    """Test EncodedProtocolDFA with various encoded URLs"""
    print("\n" + "="*70)
    print("TEST 1: EncodedProtocolDFA - Percent-Encoded Protocol Detection")
    print("="*70)
    
    dfa = EncodedProtocolDFA()
    
    test_cases = [
        ("callback=%68%74%74%70%3A%2F%2Fevil.com", True, "Encoded http://"),
        ("url=normal_value", False, "Normal query parameter"),
        ("redirect=%68%74%74%70", False, "Partial encoding (http only)"),
        ("next=page&data=%3A%2F%2F", True, "Encoded :// sequence"),
    ]
    
    for query, should_trigger, description in test_cases:
        result = dfa.check(query)
        status = "✓ PASS" if result["triggered"] == should_trigger else "✗ FAIL"
        print(f"\n{status} | {description}")
        print(f"  Query: {query}")
        print(f"  Triggered: {result['triggered']}")
        print(f"  Risk Score: {result['risk_score']}")
        print(f"  Reason: {result['reason']}")


def test_fragment_redirect_dfa():
    """Test FragmentRedirectDFA with fragment-based redirects"""
    print("\n" + "="*70)
    print("TEST 2: FragmentRedirectDFA - Fragment-Based Redirect Detection")
    print("="*70)
    
    dfa = FragmentRedirectDFA()
    
    test_cases = [
        ("#//evil.com", True, "Double slash redirect"),
        ("#/http://malicious.site", True, "HTTP protocol in fragment"),
        ("#section", False, "Normal fragment anchor"),
        ("", False, "Empty fragment"),
    ]
    
    for fragment, should_trigger, description in test_cases:
        result = dfa.check(fragment)
        status = "✓ PASS" if result["triggered"] == should_trigger else "✗ FAIL"
        print(f"\n{status} | {description}")
        print(f"  Fragment: {fragment}")
        print(f"  Triggered: {result['triggered']}")
        print(f"  Risk Score: {result['risk_score']}")
        print(f"  Reason: {result['reason']}")


def test_shortener_dfa():
    """Test ShortenerDFA with URL shortener domains"""
    print("\n" + "="*70)
    print("TEST 3: ShortenerDFA - URL Shortener Domain Detection")
    print("="*70)
    
    dfa = ShortenerDFA()
    
    test_cases = [
        ("bit.ly", True, "bit.ly shortener"),
        ("tinyurl.com", True, "tinyurl.com shortener"),
        ("t.co", True, "t.co shortener"),
        ("is.gd", True, "is.gd shortener"),
        ("google.com", False, "Normal domain"),
        ("bit.ly.phishing.com", False, "Fake shortener subdomain"),
    ]
    
    for hostname, should_trigger, description in test_cases:
        result = dfa.check(hostname)
        status = "✓ PASS" if result["triggered"] == should_trigger else "✗ FAIL"
        print(f"\n{status} | {description}")
        print(f"  Hostname: {hostname}")
        print(f"  Triggered: {result['triggered']}")
        print(f"  Risk Score: {result['risk_score']}")
        print(f"  Reason: {result['reason']}")


def test_credential_path_dfa():
    """Test CredentialPathDFA with credential harvesting paths"""
    print("\n" + "="*70)
    print("TEST 4: CredentialPathDFA - Credential Harvesting Path Detection")
    print("="*70)
    
    dfa = CredentialPathDFA()
    
    test_cases = [
        ("/login", True, "Login path"),
        ("/verify/account", True, "Verify path"),
        ("/user/update", True, "Update path"),
        ("/auth/signin", True, "Auth path"),
        ("/session/new", True, "Session path"),
        ("/about", False, "Normal path"),
        ("/home", False, "Home path"),
    ]
    
    for path, should_trigger, description in test_cases:
        result = dfa.check(path)
        status = "✓ PASS" if result["triggered"] == should_trigger else "✗ FAIL"
        print(f"\n{status} | {description}")
        print(f"  Path: {path}")
        print(f"  Triggered: {result['triggered']}")
        print(f"  Risk Score: {result['risk_score']}")
        print(f"  Reason: {result['reason']}")


def test_suspicious_tld_dfa():
    """Test SuspiciousTLDDFA with risky TLDs"""
    print("\n" + "="*70)
    print("TEST 5: SuspiciousTLDDFA - Suspicious TLD Detection")
    print("="*70)
    
    dfa = SuspiciousTLDDFA()
    
    test_cases = [
        ("malicious.xyz", True, ".xyz TLD"),
        ("phishing.tk", True, ".tk TLD"),
        ("scam.top", True, ".top TLD"),
        ("russian.ru", True, ".ru TLD"),
        ("chinese.cn", True, ".cn TLD"),
        ("google.com", False, ".com TLD (normal)"),
        ("example.org", False, ".org TLD (normal)"),
    ]
    
    for hostname, should_trigger, description in test_cases:
        result = dfa.check(hostname)
        status = "✓ PASS" if result["triggered"] == should_trigger else "✗ FAIL"
        print(f"\n{status} | {description}")
        print(f"  Hostname: {hostname}")
        print(f"  Triggered: {result['triggered']}")
        print(f"  Risk Score: {result['risk_score']}")
        print(f"  Reason: {result['reason']}")


def test_layer3_integration():
    """Test full Layer3 integration with all DFAs"""
    print("\n" + "="*70)
    print("TEST 6: Layer3 Integration - Complete Threat Analysis")
    print("="*70)
    
    layer3 = Layer3()
    
    test_urls = [
        "http://bit.ly/malware#//evil.com",
        "http://phishing.xyz/login?redirect=%68%74%74%70%3A%2F%2Fevil.com",
        "http://google.com/search?q=test",
    ]
    
    for url in test_urls:
        print(f"\n{'─'*70}")
        print(f"Analyzing URL: {url}")
        print('─'*70)
        
        result = layer3.analyze(url)
        
        print(f"\nTriggered Checks: {result['triggered_count']}/{result['total_checks']}")
        print(f"Total Layer Risk Score: {result['layer_risk_score']:.1f}")
        
        print("\nDetailed Results:")
        for check_name, check_result in result['checks'].items():
            if check_result['triggered']:
                print(f"  ⚠ {check_name.upper()}: {check_result['reason']}")
                print(f"    Risk Score: {check_result['risk_score']}")
        
        if result['triggered_count'] == 0:
            print("  ✓ No threats detected")


def main():
    """Run all tests"""
    print("\n" + "█"*70)
    print("█" + " "*68 + "█")
    print("█" + "  Layer 3 DFA Extensions - Comprehensive Test Suite".center(68) + "█")
    print("█" + " "*68 + "█")
    print("█"*70)
    
    test_encoded_protocol_dfa()
    test_fragment_redirect_dfa()
    test_shortener_dfa()
    test_credential_path_dfa()
    test_suspicious_tld_dfa()
    test_layer3_integration()
    
    print("\n" + "█"*70)
    print("█" + "  All tests completed!".center(68) + "█")
    print("█"*70 + "\n")


if __name__ == "__main__":
    main()
