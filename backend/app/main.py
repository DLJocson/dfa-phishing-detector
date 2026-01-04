"""  
===========================================
FASTAPI MAIN APPLICATION
===========================================
Provides REST API endpoints for phishing URL detection
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, List

from .logic.tokenizer import TokenizerDFA
from .logic.layer1 import Layer1
from .logic.layer2 import Layer2
from .logic.layer3 import Layer3
from .models.risk_scorer import RiskScorer


# ========================================
# APP INITIALIZATION
# ========================================

app = FastAPI(
    title="Hierarchical DFA-Based Phishing URL Detector",
    description="A multi-layer DFA system for detecting and classifying phishing URLs",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ========================================
# DFA COMPONENTS
# ========================================

tokenizer = TokenizerDFA()
layer1 = Layer1()
layer2 = Layer2()
layer3 = Layer3()
risk_scorer = RiskScorer()


# ========================================
# REQUEST/RESPONSE MODELS
# ========================================

class URLRequest(BaseModel):
    """Request model for URL analysis"""
    url: str = Field(..., description="The URL to analyze")


class URLResponse(BaseModel):
    """Response model for URL analysis"""
    url: str
    tokens: Dict[str, str]
    hostname_components: Dict[str, str]
    layers: List[Dict]
    risk_analysis: Dict
    summary: Dict


# ========================================
# API ENDPOINTS
# ========================================


@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "Hierarchical DFA-Based Phishing URL Detector API",
        "version": "1.0.0",
        "endpoints": {
            "analyze": "/analyze (POST)",
            "health": "/health (GET)"
        }
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy"}


@app.post("/analyze", response_model=URLResponse)
async def analyze_url(request: URLRequest):
    """
    Main endpoint: Analyze URL using hierarchical DFA system
    Returns complete risk assessment with layer details
    """
    try:
        url = request.url.strip()
        
        if not url:
            raise HTTPException(status_code=400, detail="URL cannot be empty")
        
        # Tokenize
        tokens = tokenizer.tokenize(url)
        hostname_components = tokenizer.get_hostname_components(tokens["hostname"])
        
        # Run DFA layers
        layer1_result = layer1.analyze(url)
        layer2_result = layer2.analyze(url)
        layer3_result = layer3.analyze(url)
        all_layers = [layer1_result, layer2_result, layer3_result]
        
        # Calculate risk
        risk_analysis = risk_scorer.analyze(all_layers)
        
        # Create summary
        summary = {
            "risk_level": risk_analysis["risk_level"],
            "risk_score": risk_analysis["risk_score"],
            "total_triggered": risk_analysis["total_checks_triggered"],
            "total_checks": risk_analysis["total_checks"],
            "is_suspicious": risk_analysis["risk_level"] not in ["Benign", "Low"]
        }
        
        return URLResponse(
            url=url,
            tokens=tokens,
            hostname_components=hostname_components,
            layers=all_layers,
            risk_analysis=risk_analysis,
            summary=summary
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing URL: {str(e)}")


@app.get("/tokenize")
async def tokenize_url(url: str):
    """Utility endpoint: Tokenize URL into components"""
    try:
        tokens = tokenizer.tokenize(url)
        hostname_components = tokenizer.get_hostname_components(tokens["hostname"])
        
        return {
            "url": url,
            "tokens": tokens,
            "hostname_components": hostname_components
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error tokenizing URL: {str(e)}")


# ========================================
# SERVER STARTUP
# ========================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)

