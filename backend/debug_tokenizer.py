#!/usr/bin/env python3
"""Debug tokenizer output for Layer 1 DFA"""

from app.logic.tokenizer import TokenizerDFA

tokenizer = TokenizerDFA()

test_url = "https://www.paypal.com.secure-login.tk/path?query=value"
tokens = tokenizer.tokenize(test_url)
hostname_components = tokenizer.get_hostname_components(tokens['hostname'])

print("URL:", test_url)
print("\nTokens:")
print(f"  schema: '{tokens['schema']}'")
print(f"  hostname: '{tokens['hostname']}'")
print(f"  path: '{tokens['path']}'")
print(f"  query: '{tokens['query']}'")

print("\nHostname Components:")
print(f"  subdomain: '{hostname_components['subdomain']}'")
print(f"  domain: '{hostname_components['domain']}'")
print(f"  tld: '{hostname_components['tld']}'")
