/**
 * Main Application: React app for phishing URL detection
 * - State management for analysis results
 * - API communication with backend
 */

import React, { useState } from 'react';
import './App.css';
import InputBar from './components/InputBar';
import ResultsCard from './components/ResultsCard';
import DFAVisualization from './visualization/DFAVisualization';
import DarkModeToggle from './components/DarkModeToggle';
import logo from './assets/logo.png';


const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';


function App() {
  const [analysis, setAnalysis] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

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

  return (
    <div className="App">
      <header className="app-header" style={{ position: 'relative' }}>

  <div style={{ position: 'absolute', top: 20, right: 20 }}>
    <DarkModeToggle />
  </div>

  <div className="header-content">
    <div className="header-title">
      <img src={logo} alt="App Logo" className="app-logo" />
      <h1 className="app-title">
        Hierarchical DFA-Based Phishing URL Detector
      </h1>
    </div>

    <p className="app-subtitle">
      Multi-layer deterministic finite automata for accurate phishing detection
    </p>
  </div>

</header>

      <main className="app-main">
    {/* additional - 2 Panels */}
    <div className="card-panels">
    {/* additional - left panel input */}
    <div className="card-panel">
      <InputBar onAnalyze={handleAnalyze} isLoading={isLoading} />
    </div>

    {/* additional - right panel input */}
    <div className="card-panel">
      {error && (
        <div className="error-message">
          <span className="error-icon">⚠️</span>
          <span>{error}</span>
        </div>
      )}

      {analysis ? (
        <ResultsCard analysis={analysis} />
      ) : (
        <div className="placeholder">
          <h3>Analysis Results</h3>
          <p>Results will appear here after analyzing a URL.</p>
        </div>
      )}
    </div>
  </div>

  {/* additional - DFA viz below */}
  {analysis && (
    <div className="dfa-panel">
      <DFAVisualization analysis={analysis} />
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
