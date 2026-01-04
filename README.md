# DFA-Based Phishing URL Detection

A hierarchical deterministic finite automata (DFA) system for phishing URL detection and classification.

## General Information

This project implements a multi-layer DFA architecture that analyzes URLs across three detection layers:

- **Layer 1 (Basic)**: Length, schema, and TLD validation
- **Layer 2 (Advanced)**: Homograph detection, subdomain analysis, and Punycode identification
- **Layer 3 (Threat)**: Chained URL detection, dynamic pattern analysis, and redirect parameter flagging

### Architecture

**Backend (FastAPI)**
- Tokenizer DFA for URL parsing
- Three independent analysis layers
- Risk scoring engine combining all layers
- REST API with Swagger documentation

**Frontend (React.js)**
- URL input interface
- Real-time analysis results
- Risk level visualization
- DFA state transition display

### Components

```
backend/
  ├── app/
  │   ├── logic/          # DFA implementations (tokenizer, layer1-3)
  │   ├── models/         # Risk scoring engine
  │   └── main.py         # API endpoints
  └── requirements.txt
  
frontend/
  ├── src/
  │   ├── components/     # UI components
  │   └── visualization/  # DFA visualization
  ├── public/
  └── package.json
```

## How to Run

### Prerequisites
- Python 3.8+
- Node.js 16+
- npm or yarn

### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate          # macOS/Linux
# OR
venv\Scripts\activate             # Windows

# Install dependencies
pip install -r requirements.txt

# Start server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Backend API: `http://localhost:8000`

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Optional: Create .env file
# REACT_APP_API_URL=http://localhost:8000

# Start development server
npm start
```

Frontend: `http://localhost:3000`

### API Endpoints

- `POST /analyze` - Analyze a URL
- `GET /tokenize` - Tokenize a URL into components
- `GET /docs` - Interactive API documentation (Swagger UI)
- `GET /redoc` - API reference (ReDoc)
