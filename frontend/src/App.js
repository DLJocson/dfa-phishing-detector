/**
 * Main Application: React app for phishing URL detection
 * - State management for analysis results
 * - API communication with backend
 */

import React, { useState } from 'react';
import './App.css';
import InputBar from './components/InputBar';
import RiskSummaryCard from './components/RiskSummaryCard';
import UrlComponentsCard from './components/UrlComponentsCard';
import ResultsCard from './components/ResultsCard';
import DiagnosticDetailsCard from './components/DiagnosticDetailsCard';
import DFAVisualization from './visualization/DFAVisualization';
import SystemOverview from './components/SystemOverview';
import Header from './components/Header';


const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';


function App() {
  const [analysis, setAnalysis] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleReset = () => {
    setAnalysis(null);
    setError(null);
    setIsLoading(false);
  };

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
      // Defensive: ensure layers is always an array
      setAnalysis({
        ...data,
        layers: Array.isArray(data.layers) ? data.layers : [],
      });
    } catch (err) {
      setError(err.message || 'An error occurred while analyzing the URL');
      console.error('Analysis error:', err);
    } finally {
      setIsLoading(false);
    }
  };


  return (
    <div className="App">
      <Header onReset={handleReset} />

      <main className="app-main">
    {/* additional - 2 Panels */}
    <div className="card-panels">
      {/* Left Panel: URL input, Risk, URL Components */}
      <div className={`left-panel flex flex-col gap-6 p-6 ${analysis ? 'has-analysis' : ''}`}>
        <div className="panel-header">
          <h3 className="panel-title">URL Analysis</h3>
        </div>
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
      <div className={`card-panel ${analysis ? 'has-analysis' : ''}`}>
        <div className="panel-header">
          <h3 className="panel-title">DFA Layer Analysis</h3>
        </div>
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

    {/* Diagnostic Details panel below, spanning both columns */}
    {analysis && (
      <div className="diagnostic-panel full-width with-analysis">
        <DiagnosticDetailsCard analysis={analysis} />
      </div>
    )}

    {/* DFA State Transition panel below, spanning both columns */}
    {analysis && (
      <div className="dfa-panel full-width">
        <DFAVisualization analysis={analysis} />
      </div>
    )}

    {/* System Overview panel below, spanning both columns - only show when no analysis */}
    {!analysis && (
      <div className="system-overview-panel full-width">
        <SystemOverview />
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
