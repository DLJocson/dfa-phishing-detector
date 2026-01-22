import React from 'react';
import './SystemOverview.css';

const SystemOverview = () => {
  return (
    <div className="system-overview-card">
      <div className="card-header">
        <h3 className="card-title">System Overview</h3>
      </div>
      
      <div className="overview-section">
        <h4 className="section-title">General Overview</h4>
        <p className="section-text">
          This system utilizes a Hierarchical Deterministic Finite Automata (DFA) architecture to detect phishing URLs in real-time. Unlike traditional regex matching, our approach maintains state across multiple layers of analysis to identify complex threat patterns efficiently.
        </p>
      </div>

      <div className="tokenizer-section">
        <div className="tokenizer-header">
          <span className="tokenizer-icon">⚙️</span>
          <h5 className="tokenizer-title">Tokenizer DFA</h5>
        </div>
        <p className="tokenizer-description">
          The initial stage that parses the raw string into semantic tokens (Schema, Host, Path, Query) to feed into the subsequent hierarchical layers.
        </p>
      </div>

      <div className="layers-grid">
        <div className="layer-card layer-1">
          <div className="layer-header">
            <span className="layer-icon">🔍</span>
            <h5 className="layer-title">Layer 1 (Basic)</h5>
          </div>
          <p className="layer-description">
            Rapidly filters low-hanging fruit by validating URL length, checking for non-standard schemas (e.g., http://), and cross-referencing Top-Level Domains (TLDs) against a known blocklist.
          </p>
        </div>

        <div className="layer-card layer-2">
          <div className="layer-header">
            <span className="layer-icon">🔬</span>
            <h5 className="layer-title">Layer 2: Advanced Heuristics</h5>
          </div>
          <p className="layer-description">
            Performs deep inspection for IDN homograph attacks (visually similar characters), suspicious subdomain depth, and Punycode obfuscation attempts.
          </p>
        </div>

        <div className="layer-card layer-3">
          <div className="layer-header">
            <span className="layer-icon">⚡</span>
            <h5 className="layer-title">Layer 3: Threat Patterning</h5>
          </div>
          <p className="layer-description">
            Analyzes query parameters for open redirect chains, dynamic DNS generation patterns, and malicious payload signatures.
          </p>
        </div>
      </div>
    </div>
  );
};

export default SystemOverview;
