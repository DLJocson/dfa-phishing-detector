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
import Header from './components/Header';
import RiskSummaryCard from './components/RiskSummaryCard';
import UrlComponentsCard from './components/UrlComponentsCard';
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
      <Header />

      <main className="app-main">
    {/* additional - 2 Panels */}
    <div className="card-panels">
      {/* Left Panel: URL input, Risk, URL Components */}
      <div className="left-panel flex flex-col gap-6 p-6">
        <InputBar onAnalyze={handleAnalyze} isLoading={isLoading} />
        {analysis && (
          <>
            <div className="w-full">
              <RiskSummaryCard analysis={analysis} />
            </div>
            <div className="w-full">
              <UrlComponentsCard analysis={analysis} />
            </div>
          </>
        )}
      </div>

      {/* Right Panel: DFA Layer Analysis */}
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
          <h3>Layer Analysis</h3>
          <p>Run an analysis to see which DFA checks triggered per layer.</p>
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
