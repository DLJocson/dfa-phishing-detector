# Hierarchical DFA-Based Phishing URL Detection and Classification

A multi-layer deterministic finite automata (DFA) system for accurate phishing URL detection and classification. This project implements a hierarchical architecture that analyzes URLs at multiple levels to identify suspicious patterns and classify risk levels.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [System Design](#system-design)
- [API Documentation](#api-documentation)
- [Project Structure](#project-structure)
- [Contributing](#contributing)

## 🎯 Overview

This system uses a hierarchical approach with three distinct DFA layers to detect phishing URLs:

- **Layer 1 (Basic)**: Length, Schema, TLD checks
- **Layer 2 (Advanced)**: Homographs, Subdomain patterns, Punycode detection
- **Layer 3 (Threat)**: Chained URLs, Dynamic patterns, Redirect parameters

Each layer's outputs are combined using a weighted risk scoring system to classify URLs as Benign, Low, Medium, High, or Critical risk.

## ✨ Features

- **Multi-Layer DFA Architecture**: Three independent DFA layers for comprehensive analysis
- **URL Tokenization**: Automatic parsing of URLs into schema, hostname, path, and query components
- **Risk Scoring**: Weighted scoring system with transparent breakdown
- **Real-time Analysis**: Fast processing suitable for real-time detection
- **Visual DFA State Transitions**: Interactive visualization of DFA state transitions
- **User-Friendly Interface**: Modern React-based UI with detailed results display

## 🏗️ Architecture

### Backend (FastAPI)

The backend implements the core DFA logic:

- **Tokenizer DFA**: Parses URLs into fundamental components
- **Layer 1 DFA**: Basic pattern matching (length, schema, TLD)
- **Layer 2 DFA**: Advanced pattern detection (homographs, subdomains, punycode)
- **Layer 3 DFA**: Threat detection (chained URLs, dynamic patterns, redirects)
- **Risk Scorer**: Combines layer outputs into risk scores and classifications

### Frontend (React)

The frontend provides:

- URL input interface with example URLs
- Detailed analysis results display
- DFA state transition visualization
- Risk level indicators with color coding

## 📦 Installation

### Prerequisites

- Python 3.8+
- Node.js 16+
- npm or yarn

### Backend Setup

1. Navigate to the backend directory:
```bash
cd backend
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the FastAPI server:
```bash
python -m app.main
# Or using uvicorn directly:
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`

### Frontend Setup

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Create a `.env` file (optional, defaults to `http://localhost:8000`):
```bash
REACT_APP_API_URL=http://localhost:8000
```

4. Start the development server:
```bash
npm start
```

The frontend will be available at `http://localhost:3000`

## 🚀 Usage

### Web Interface

1. Start both backend and frontend servers
2. Open `http://localhost:3000` in your browser
3. Enter a URL in the input field
4. Click "Analyze" or use one of the example URLs
5. View the detailed analysis results and DFA visualizations

### API Usage

#### Analyze a URL

```bash
curl -X POST "http://localhost:8000/analyze" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

#### Tokenize a URL

```bash
curl "http://localhost:8000/tokenize?url=https://example.com/path?query=value"
```

## 🔬 System Design

### 1. Preprocessing and Tokenizer DFA

- **Preprocessing**: Converts URLs to lowercase and decodes URL-encoded characters
- **Tokenizer DFA**: Parses URLs into:
  - Schema (protocol): `http`, `https`, etc.
  - Hostname: Full domain name
  - Path: URL path segments
  - Query: Query parameters

### 2. Layer 1 (Basic DFA)

- **Length DFA**: Flags URLs exceeding a configurable threshold (default: 75 characters)
- **Schema DFA**: Detects non-standard or suspicious protocols (`file://`, `data:`, etc.)
- **TLD DFA**: Identifies high-risk top-level domains (`.zip`, `.tk`, `.link`, etc.)

### 3. Layer 2 (Advanced DFA)

- **Homograph DFA**: Detects non-ASCII characters (IDN homograph attacks)
- **Subdomain DFA**: Analyzes subdomain depth and brand-jacking patterns
- **Punycode DFA**: Identifies Punycode encoding (`xn--`) in hostnames

### 4. Layer 3 (Threat DFA)

- **Chained DFA**: Detects URLs within URLs (chained redirects)
- **Dynamic DFA**: Identifies dynamic DNS patterns and excessive query parameters
- **Redirect DFA**: Flags common redirect parameter names (`?url=`, `?redirect=`, etc.)

### 5. Classification & Risk Scoring

- Weighted combination of all layer outputs
- Risk levels: **Benign** (0-2), **Low** (2-5), **Medium** (5-8), **High** (8-12), **Critical** (12+)
- Transparent score breakdown showing which checks triggered and why

## 📚 API Documentation

### Endpoints

#### `POST /analyze`

Analyzes a URL using the hierarchical DFA system.

**Request Body:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "tokens": {
    "schema": "https",
    "hostname": "example.com",
    "path": "",
    "query": "",
    "hostname_components": {
      "subdomain": "",
      "domain": "example",
      "tld": "com"
    }
  },
  "layers": [...],
  "risk_analysis": {
    "risk_score": 0.0,
    "risk_level": "Benign",
    "risk_color": "#10b981",
    ...
  },
  "summary": {
    "risk_level": "Benign",
    "risk_score": 0.0,
    "total_triggered": 0,
    "total_checks": 9,
    "is_suspicious": false
  }
}
```

#### `GET /tokenize`

Tokenizes a URL into its components.

**Query Parameters:**
- `url`: The URL to tokenize

**Response:**
```json
{
  "url": "https://example.com/path?query=value",
  "tokens": {
    "schema": "https",
    "hostname": "example.com",
    "path": "/path",
    "query": "query=value"
  },
  "hostname_components": {
    "subdomain": "",
    "domain": "example",
    "tld": "com"
  }
}
```

#### `GET /health`

Health check endpoint.

#### `GET /`

API information and available endpoints.

### Interactive API Documentation

When the backend is running, visit:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## 📁 Project Structure

```
dfa-phishing-detector/
├── backend/                 # Python (FastAPI)
│   ├── app/
│   │   ├── logic/
│   │   │   ├── tokenizer.py    # Tokenizer DFA
│   │   │   ├── layer1.py       # Basic DFA (Length, Schema, TLD)
│   │   │   ├── layer2.py       # Advanced DFA (Homographs, etc.)
│   │   │   └── layer3.py       # Threat DFA (Redirects, etc.)
│   │   ├── models/
│   │   │   └── risk_scorer.py  # Risk scoring and classification
│   │   └── main.py             # API endpoints
│   └── requirements.txt
├── frontend/                # React.js
│   ├── src/
│   │   ├── components/         # UI components
│   │   │   ├── InputBar.jsx
│   │   │   ├── InputBar.css
│   │   │   ├── ResultsCard.jsx
│   │   │   └── ResultsCard.css
│   │   ├── visualization/      # DFA visualizations
│   │   │   ├── DFAVisualization.jsx
│   │   │   └── DFAVisualization.css
│   │   ├── App.js
│   │   ├── App.css
│   │   ├── index.js
│   │   └── index.css
│   ├── public/
│   │   └── index.html
│   └── package.json
└── README.md
```

## 🎓 Academic Context

This project was developed for **COSC 203 - Automata and Language Theory** at the Polytechnic University of the Philippines.

### Team Members

- Baptista, Nicko Adrian
- Delos Reyes, Ariane Joy
- Martinez, Bouie
- Madelo, Mark Anthony
- Bermudez, Mark Daniel
- Jocson, Dan Louie

### References

The implementation is based on research in:
- Deterministic Finite Automata in phishing URL detection
- Hybrid models combining automata theory with machine learning
- Advanced automata applications for cybersecurity
- DFA optimization techniques for real-time processing

## 🔧 Configuration

### Backend Configuration

Modify thresholds and weights in the respective modules:

- **Layer 1**: `backend/app/logic/layer1.py` - Adjust length threshold
- **Layer 2**: `backend/app/logic/layer2.py` - Adjust subdomain depth limit
- **Risk Scorer**: `backend/app/models/risk_scorer.py` - Modify layer weights and thresholds

### Frontend Configuration

Set the API URL in `frontend/.env`:
```
REACT_APP_API_URL=http://localhost:8000
```

## 🧪 Testing

### Example URLs to Test

**Suspicious:**
- `http://paypal-secure-verify.com/login`
- `https://www.google.com.secure-login.tk`
- `file://malicious-script.exe`

**Benign:**
- `https://www.google.com`
- `https://github.com`
- `https://www.example.com/path/to/resource`

## 🤝 Contributing

This is an academic project, but suggestions and improvements are welcome. Please ensure any contributions maintain the DFA-based approach and hierarchical architecture.

## 📝 License

This project is developed for academic purposes as part of COSC 203 coursework.

## 🙏 Acknowledgments

- Research papers on DFA-based phishing detection
- FastAPI and React.js communities
- Automata theory foundations

---

**Note**: This system is designed for educational and research purposes. For production use in security-critical applications, additional validation and testing are recommended.
