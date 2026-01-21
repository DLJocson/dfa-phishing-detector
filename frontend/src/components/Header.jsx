import React, { useState } from 'react';
import DarkModeToggle from './DarkModeToggle';
import logo from '../assets/logo.png';
import './Header.css';

const Header = ({ onReset }) => {
  const [isResetting, setIsResetting] = useState(false);

  const handleReset = () => {
    if (onReset) {
      setIsResetting(true);
      
      // Add a brief delay for the animation
      setTimeout(() => {
        onReset();
        setIsResetting(false);
      }, 300);
    }
  };

  return (
    <header className="navbar-header">
      <div className="navbar-left">
        <img src={logo} alt="App Logo" className="navbar-logo" />
        <span 
          className={`navbar-title clickable ${isResetting ? 'resetting' : ''}`} 
          onClick={handleReset}
        >
          PhishGuard: A Hierarchical DFA-Based Phishing Detection System
        </span>
      </div>
      <div className="navbar-right">
        <div className="navbar-academic">
          <span className="navbar-course">
            <span className="navbar-course-full">COSC 203 - Automata and Language Theory</span>
            <span className="navbar-course-short">COSC 203</span>
          </span>
          <span className="navbar-year">A.Y. 2025-2026</span>
        </div>
        <div className="navbar-divider" />
        <DarkModeToggle />
      </div>
    </header>
  );
};

export default Header;
