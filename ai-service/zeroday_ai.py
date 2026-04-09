from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import random

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5000"],  # Add your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ThreatInput(BaseModel):
    title: str
    content: str

def calculate_score(text):
    keywords = ["0day", "zero-day", "RCE", "exploit", "unpatched"]
    score = sum(1 for k in keywords if k in text.lower())
    return min(score / 5, 1.0)

@app.post("/analyze")
def analyze_threat(data: ThreatInput):
    score = calculate_score(data.content)

    if score > 0.7:
        risk = "Critical"
    elif score > 0.4:
        risk = "High"
    else:
        risk = "Medium"

    return {
        "ai_score": score,
        "risk_level": risk,
        "confidence": "Medium"
    }