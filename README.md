# 🔒 DFA-Based Phishing URL Detection

> A hierarchical deterministic finite automata (DFA) system for phishing URL detection and classification.

---

<div align="center">

### 👥 Group Members

| Name | Role |
|------|------|
| **Baptista, Nicko Adrian** | 💻 Frontend |
| **Delos Reyes, Ariane Joy** | 💻 Frontend |
| **Martinez, Bouie** | ⚙️ Backend |
| **Madelo, Mark Anthony** | ⚙️ Backend |
| **Bermudez, Mark Daniel** | ⚙️ Backend |
| **Jocson, Dan Louie** | 📋 Project Manager |

</div>

---

## 📋 General Information

This project implements a multi-layer DFA architecture that analyzes URLs across three detection layers:

| Layer | Focus | Features |
|-------|-------|----------|
| **Layer 1** | 🔍 Basic | Length, schema, and TLD validation |
| **Layer 2** | ⚡ Advanced | Homograph detection, subdomain analysis, and Punycode identification |
| **Layer 3** | 🚨 Threat | Chained URL detection, dynamic pattern analysis, and redirect parameter flagging |

---


### 🏗️ Architecture

The system uses a FastAPI backend to analyze URLs through a multi-layer DFA approach, combining basic, advanced, and threat-focused checks. The backend exposes a REST API for analysis and risk scoring. The React.js frontend provides a user interface for URL input, real-time results, risk visualization, and DFA state transitions.

---

### 📁 Components

```
backend/
  ├── app/
  │   ├── logic/          # 🧠 DFA implementations (tokenizer, layer1-3)
  │   ├── models/         # 📊 Risk scoring engine
  │   └── main.py         # 🔌 API endpoints
  └── requirements.txt
  
frontend/
  ├── src/
  │   ├── components/     # 🧩 UI components
  │   └── visualization/  # 🎨 DFA visualization
  ├── public/
  └── package.json
```

---

## 🚀 How to Run

### ✅ Prerequisites Check

Ensure you have these installed:

| Tool | Version | Link |
|------|---------|------|
| **Python** | 3.8+ | [Download](https://www.python.org/downloads/) |
| **Node.js** | 16+ | [Download](https://nodejs.org/) |
| **npm** | (comes with Node.js) | Included |

---

### 🎯 Quick Start


**Terminal 1 - Backend**
```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

**Terminal 2 - Frontend**
```bash
cd frontend
npm install
npm start
```


---

### 🌐 Accessing the Application

Once both servers are running:

| Service | URL | Description |
|---------|-----|-------------|
| **Frontend** | [http://localhost:3000](http://localhost:3000) | Main application UI |
| **Backend API** | [http://localhost:8000/docs](http://localhost:8000/docs) | Swagger documentation |

---


## 📚 Course Information

<div align="center">

### 📜 In Partial Fulfillment for the Course

**COSC 203 – Automata and Language Theory**

---

### 🎓 Institution

**Polytechnic University of the Philippines**

Bachelor of Science in Computer Science • 3rd Year, 1st Semester

Academic Year 2025-2026
</div>

---

<div align="center">

**Made with ❤️ for Automata**

</div>
