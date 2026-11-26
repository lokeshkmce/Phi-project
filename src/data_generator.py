"""
Synthetic Clinical Data Generator for PHI-Gateway
Generates diverse synthetic clinical notes (Tamil Nadu healthcare context)
and outputs BIO token annotations for NER training and evaluation.
"""

import json
import random
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"

PATIENT_NAMES = [
    "Murugan Natarajan", "Palanisamy Gounder", "Priya Balasubramanian", "Revathi Sundaram",
    "Karthik Selvaraj", "Anandhi Venkatachalam", "Saravanan Ranganathan", "Meenakshi Sundaram",
    "Suresh Kumar", "Kavitha Rajendran", "Dhanalakshmi S", "Senthil Nathan", "Geetha Parthiban"
]

CLINICIAN_NAMES = [
    "Dr. K. Senthil Kumar", "Dr. R. Subramaniam", "Dr. Meenakshi Palanisamy",
    "Dr. V. Ramakrishnan", "Dr. S. Sundararajan", "Dr. Anitha Mohan", "Dr. T. Natarajan"
]

HOSPITALS = [
    "Salem General Hospital", "Kovai Medical Center and Hospital (KMCH)",
    "Apollo Hospitals Greams Road, Chennai", "Ganga Hospital Coimbatore",
    "Christian Medical College (CMC) Vellore", "Tirunelveli Medical College Hospital"
]

CITIES = ["Salem", "Coimbatore", "Chennai", "Madurai", "Tiruchirappalli", "Vellore", "Erode"]

STREETS = [
    "No. 42, Omalur Main Road", "Avinashi Road", "Greams Road",
    "Anna Salai", "Palayamkottai High Road", "Thillai Nagar Main Road"
]

DIAGNOSES = [
    ("Type 2 Diabetes Mellitus", "Prescribed Metformin 500mg BID. HbA1c at 7.4%."),
    ("Coronary Artery Disease", "Underwent coronary angiogram. Prescribed Atorvastatin 40mg."),
    ("Parkinson's disease", "Presents with resting tremor and bradykinesia. Prescribed Levodopa 100mg."),
    ("Hypertension Stage 2", "Blood pressure 160/95 mmHg. Initiated Amlodipine 5mg daily.")
]

def generate_sample_note():
    p_name = random.choice(PATIENT_NAMES)
    c_name = random.choice(CLINICIAN_NAMES)
    hosp = random.choice(HOSPITALS)
    city = random.choice(CITIES)
    street = random.choice(STREETS)
    diag, plan = random.choice(DIAGNOSES)
    
    phone = f"+91 {random.randint(60000, 99999)} {random.randint(10000, 99999)}"
    mrn = f"MRN-{random.randint(100000, 999999)}"
    pin = f"6{random.randint(10000, 49999)}"
    date = f"{random.randint(1, 28):02d}/{random.randint(1, 12):02d}/2026"
    
    text = (
        f"CLINICAL CONSULTATION NOTE\n"
        f"Patient: {p_name} | DOB: {date} | MRN: {mrn}\n"
        f"Referring Provider: {c_name}, MD\n"
        f"Facility: {hosp}, {street}, {city}, TN {pin}\n"
        f"Contact: {phone}\n\n"
        f"Assessment: {diag}. {plan}\n"
        f"Signed: {c_name}"
    )
    return text

if __name__ == "__main__":
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    notes = [generate_sample_note() for _ in range(50)]
    print(f"Generated {len(notes)} synthetic clinical notes.")
