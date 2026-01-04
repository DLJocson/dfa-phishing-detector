/**
 * ============================================
 * MAIN APPLICATION COMPONENT
 * ============================================
 * React application for phishing URL detection
 * Manages state and API communication
 */

import React, { useState } from 'react';
import './App.css';
import InputBar from './components/InputBar';
import ResultsCard from './components/ResultsCard';
import DFAVisualization from './visualization/DFAVisualization';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';


// ============================================
// MAIN APP COMPONENT
// ============================================

function App() {
  // State management
  const [analysis, setAnalysis] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  // ----------------------------------------
  // API Handler
  // ----------------------------------------
  
  const handleAnalyze = async (url) => {
    setIsLoading(true);
    setError(null);
    setAnalysis(null);

    try {
      const response = await fetch(`${API_BASE_URL}/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to analyze URL');
      }

      const data = await response.json();
      setAnalysis(data);
    } catch (err) {
      setError(err.message || 'An error occurred while analyzing the URL');
      console.error('Analysis error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  // ----------------------------------------
  // Render
  // ----------------------------------------
  
  return (
    <div className="App">
      <header className="app-header">
        <div className="header-content">
          <h1 className="app-title">
            <span className="title-icon">🔒</span>
            Hierarchical DFA-Based Phishing URL Detector
          </h1>
          <p className="app-subtitle">
            Multi-layer deterministic finite automata for accurate phishing detection
          </p>
        </div>
      </header>

      <main className="app-main">
        <InputBar onAnalyze={handleAnalyze} isLoading={isLoading} />

        {error && (
          <div className="error-message">
            <span className="error-icon">⚠️</span>
            <span>{error}</span>
          </div>
        )}

        {analysis && (
          <>
            <ResultsCard analysis={analysis} />
            <DFAVisualization analysis={analysis} />
          </>
        )}

        {!analysis && !isLoading && !error && (
          <div className="welcome-message">
            <div className="welcome-icon">🛡️</div>
            <h2>Welcome to the Phishing URL Detector</h2>
            <p>
              Enter a URL above to analyze it using our hierarchical DFA system.
              The system will check for suspicious patterns across multiple layers
              and provide a comprehensive risk assessment.
            </p>
            <div className="features-list">
              <div className="feature-item">
                <span className="feature-icon">✓</span>
                <span>Layer 1: Basic checks (Length, Schema, TLD)</span>
              </div>
              <div className="feature-item">
                <span className="feature-icon">✓</span>
                <span>Layer 2: Advanced checks (Homographs, Subdomain, Punycode)</span>
              </div>
              <div className="feature-item">
                <span className="feature-icon">✓</span>
                <span>Layer 3: Threat checks (Chained URLs, Dynamic patterns, Redirects)</span>
              </div>
            </div>
          </div>
        )}
      </main>

      <footer className="app-footer">
        <p>
          Hierarchical DFA-Based Phishing URL Detection and Classification
        </p>
        <p className="footer-subtitle">COSC 203 - Automata and Language Theory</p>
      </footer>
    </div>
  );
}

export default App;

