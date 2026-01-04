/**
 * ============================================
 * INPUT BAR COMPONENT
 * ============================================
 * URL input form with example URLs for testing
 */

import React, { useState } from 'react';
import './InputBar.css';


// ============================================
// INPUT BAR COMPONENT
// ============================================

const InputBar = ({ onAnalyze, isLoading }) => {
  const [url, setUrl] = useState('');

  // ----------------------------------------
  // Event Handlers
  // ----------------------------------------
  
  const handleSubmit = (e) => {
    e.preventDefault();
    if (url.trim()) {
      onAnalyze(url.trim());
    }
  };

  const handleExampleClick = (exampleUrl) => {
    setUrl(exampleUrl);
    onAnalyze(exampleUrl);
  };

  // ----------------------------------------
  // Example URLs
  // ----------------------------------------
  
  const exampleUrls = {
    suspicious: [
      'http://paypal-secure-verify.com/login',
      'https://www.google.com.secure-login.tk',
      'file://malicious-script.exe',
    ],
    benign: [
      'https://www.google.com',
      'https://github.com',
      'https://www.example.com/path/to/resource',
    ],
  };

  return (
    <div className="input-bar-container">
      <form onSubmit={handleSubmit} className="input-form">
        <div className="input-wrapper">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Enter URL to analyze..."
            className="url-input"
            disabled={isLoading}
          />
          <button
            type="submit"
            className="analyze-button"
            disabled={isLoading || !url.trim()}
          >
            {isLoading ? 'Analyzing...' : 'Analyze'}
          </button>
        </div>
      </form>
      
      <div className="examples-section">
        <div className="examples-group">
          <span className="examples-label">Try suspicious URLs:</span>
          <div className="example-buttons">
            {exampleUrls.suspicious.map((example, idx) => (
              <button
                key={idx}
                onClick={() => handleExampleClick(example)}
                className="example-button suspicious"
                disabled={isLoading}
              >
                {example}
              </button>
            ))}
          </div>
        </div>
        <div className="examples-group">
          <span className="examples-label">Try benign URLs:</span>
          <div className="example-buttons">
            {exampleUrls.benign.map((example, idx) => (
              <button
                key={idx}
                onClick={() => handleExampleClick(example)}
                className="example-button benign"
                disabled={isLoading}
              >
                {example}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default InputBar;

