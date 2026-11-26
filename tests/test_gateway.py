"""
Comprehensive Automated Verification Test Suite for PHI-Gateway
Directly validates all user-specified edge cases, PHI categories, and security rules.
"""

import sys
from pathlib import Path

# Add project root and src to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from src.phi_engine import HybridPHIDetector, PHIDeidentifier, GeminiClinicalGateway
except ModuleNotFoundError:
    from phi_engine import HybridPHIDetector, PHIDeidentifier, GeminiClinicalGateway

def run_tests():
    print("=" * 80)
    print("RUNNING COMPREHENSIVE PHI-GATEWAY TEST SUITE")
    print("=" * 80)

    detector = HybridPHIDetector()
    deid = PHIDeidentifier(detector)
    llm = GeminiClinicalGateway()

    # --------------------------------------------------------------------------
    # 1. Complete Patient Names Detection
    # --------------------------------------------------------------------------
    t1 = "Patient Name: Daniel Christopher presented for cardiology evaluation."
    m1, map1, _ = deid.deidentify(t1)
    assert "[NAME_1]" in m1, f"Failed complete patient name: {m1}"
    assert "Daniel Christopher" not in m1, f"Original name leaked in: {m1}"
    assert "Christopher" not in m1.replace("[NAME_1]", ""), f"Partial surname leftover: {m1}"
    assert "Daniel" not in m1.replace("[NAME_1]", ""), f"Partial first name leftover: {m1}"
    print("[PASS] Test 1: Complete patient names ('Daniel Christopher' -> [NAME_1], zero leftovers).")

    # --------------------------------------------------------------------------
    # 2. Relatives' Complete Names (Emergency Contact & Family)
    # --------------------------------------------------------------------------
    t2 = "Emergency Contact: Mary Christopher (Wife) accompanied the patient."
    m2, map2, _ = deid.deidentify(t2)
    assert "[NAME_1]" in m2, f"Failed relative name: {m2}"
    assert "Mary Christopher" not in m2, f"Original relative name leaked in: {m2}"
    assert "Mary" not in m2.replace("[NAME_1]", ""), f"Partial leftover: {m2}"
    assert "Christopher" not in m2.replace("[NAME_1]", ""), f"Partial leftover: {m2}"
    print("[PASS] Test 2: Relatives' complete names ('Emergency Contact: Mary Christopher' -> [NAME_1]).")

    # --------------------------------------------------------------------------
    # 3. Repeated Person Names (Consistent Placeholder Reuse)
    # --------------------------------------------------------------------------
    t3 = (
        "Daniel Christopher was admitted in the morning. "
        "Later in the afternoon, Daniel Christopher was evaluated again. "
        "Upon discharge, Daniel Christopher was provided prescriptions."
    )
    m3, map3, _ = deid.deidentify(t3)
    assert m3.count("[NAME_1]") == 3, f"Failed repeated name placeholder reuse: {m3}"
    assert "Daniel Christopher" not in m3, f"Name leaked: {m3}"
    print("[PASS] Test 3: Repeated person names consistently reused same placeholder ([NAME_1] x 3).")

    # --------------------------------------------------------------------------
    # 4. Different People with Similar Names (Zero Collision / Surnames)
    # --------------------------------------------------------------------------
    t4 = (
        "Patient: Daniel Christopher. "
        "Emergency Contact: Mary Christopher. "
        "Daniel Christopher reported pain, but Mary Christopher remained calm. "
        "Daniel Christopher was admitted while Mary Christopher waited."
    )
    m4, map4, _ = deid.deidentify(t4)
    assert "[NAME_1]" in m4, f"Missing [NAME_1]: {m4}"
    assert "[NAME_2]" in m4, f"Missing [NAME_2]: {m4}"
    assert m4.count("[NAME_1]") == 3, f"Daniel Christopher must appear exactly 3 times as [NAME_1]: {m4}"
    assert m4.count("[NAME_2]") == 3, f"Mary Christopher must appear exactly 3 times as [NAME_2]: {m4}"
    assert "Mary [NAME_1]" not in m4, f"Corrupted partial name 'Mary [NAME_1]' detected in: {m4}"
    assert "Christopher [NAME_1]" not in m4, f"Corrupted partial name 'Christopher [NAME_1]' detected in: {m4}"
    print("[PASS] Test 4: Different people with shared surname disambiguated ('Daniel Christopher' -> [NAME_1], 'Mary Christopher' -> [NAME_2]).")

    # --------------------------------------------------------------------------
    # 5. Complete Identifiers Masking (ACC, HPL, MRN with zero visible prefixes)
    # --------------------------------------------------------------------------
    t5 = "Identifiers: ACC-77881290, Policy: HPL-998271, Chart: MRN-2026-784512."
    m5, map5, _ = deid.deidentify(t5)
    assert "[ACCOUNT_1]" in m5, f"Failed ACCOUNT: {m5}"
    assert "[HEALTH_PLAN_1]" in m5, f"Failed HEALTH_PLAN: {m5}"
    assert "[MRN_1]" in m5, f"Failed MRN: {m5}"
    # Verify NO prefix remains visible
    assert "ACC-77881290" not in m5 and "ACC-" not in m5, f"ACC prefix leaked: {m5}"
    assert "HPL-998271" not in m5 and "HPL-" not in m5, f"HPL prefix leaked: {m5}"
    assert "MRN-2026-784512" not in m5 and "MRN-" not in m5, f"MRN prefix leaked: {m5}"
    print("[PASS] Test 5: Complete identifiers masked without prefix leaks ('ACC-77881290', 'HPL-998271', 'MRN-2026-784512').")

    # --------------------------------------------------------------------------
    # 6. Age Boundaries: 45 & 89 Preserved; 96 & 102 Replaced with 90+
    # --------------------------------------------------------------------------
    t6 = "Ages: Patient is Age 96. First roommate is Age 45. Second is Age 89. Senior resident is 102 years old."
    m6, map6, _ = deid.deidentify(t6)
    assert "Age 45" in m6, f"Age 45 was incorrectly masked: {m6}"
    assert "Age 89" in m6, f"Age 89 was incorrectly masked: {m6}"
    assert "Age 96" not in m6, f"Age 96 was not masked: {m6}"
    assert "102 years old" not in m6, f"102 years old was not masked: {m6}"
    assert "Age 90+" in m6, f"Age 96 not replaced with Age 90+: {m6}"
    assert "90+ years old" in m6, f"102 years old not replaced with 90+ years old: {m6}"
    assert "[AGE_" not in m6, f"Unexpected [AGE_] placeholder found in: {m6}"
    print("[PASS] Test 6: Strict Safe Harbor age threshold verified (Age 45 & 89 preserved; 96 & 102 replaced with 90+).")

    # --------------------------------------------------------------------------
    # 7. Calendar Dates vs Relative Time & Standalone Years
    # --------------------------------------------------------------------------
    t7 = (
        "Diagnosed in 2024. Visit on 12/05/2026. "
        "Patient is 3 days post-op. Next review in 48 hours. Mobility in 2 weeks. Monitor for 7 days."
    )
    m7, map7, _ = deid.deidentify(t7)
    assert "2024" in m7, f"Standalone year 2024 was incorrectly masked: {m7}"
    assert "12/05/2026" not in m7, f"Calendar date was not masked: {m7}"
    assert "[DATE_1]" in m7, f"Calendar date placeholder missing: {m7}"
    assert "3 days post-op" in m7, f"Relative time '3 days post-op' was masked: {m7}"
    assert "48 hours" in m7, f"Relative time '48 hours' was masked: {m7}"
    assert "2 weeks" in m7, f"Relative time '2 weeks' was masked: {m7}"
    assert "7 days" in m7, f"Relative time '7 days' was masked: {m7}"
    print("[PASS] Test 7: Calendar dates masked while standalone year '2024' and relative times ('3 days', '48 hours', '2 weeks') preserved.")

    # --------------------------------------------------------------------------
    # 8. Medical Conditions Preserved (Type 2 Diabetes & Parkinson's disease)
    # --------------------------------------------------------------------------
    t8 = "Patient has Type 2 Diabetes and Parkinson's disease. Dr. Parkinson diagnosed Parkinson's disease."
    m8, map8, _ = deid.deidentify(t8)
    assert "Type 2 Diabetes" in m8, f"Medical condition 'Type 2 Diabetes' was masked in: {m8}"
    assert "Parkinson's disease" in m8, f"Eponym condition 'Parkinson's disease' was masked in: {m8}"
    assert "[CLINICIAN_1]" in m8, f"Clinician Dr. Parkinson was not masked: {m8}"
    print("[PASS] Test 8: Medical conditions ('Type 2 Diabetes', 'Parkinson's disease') preserved while clinician masked.")

    # --------------------------------------------------------------------------
    # 9. Healthcare Facility in Headings
    # --------------------------------------------------------------------------
    t9 = "GREEN VALLEY MEDICAL CENTER\nCardiology Consult"
    m9, _, _ = deid.deidentify(t9)
    assert "[FACILITY_1]" in m9, f"Failed facility heading: {m9}"
    print("[PASS] Test 9: Healthcare facility detected in document heading ('Green Valley Medical Center' -> [FACILITY_1]).")

    # --------------------------------------------------------------------------
    # 10. Complete Street Address Detection
    # --------------------------------------------------------------------------
    t10 = "Residence: 24, Rose Garden Street, Salem, TN 636001."
    m10, _, _ = deid.deidentify(t10)
    assert "[ADDRESS_1]" in m10, f"Failed street address: {m10}"
    assert "24, Rose Garden Street" not in m10, f"Street address leaked: {m10}"
    print("[PASS] Test 10: Complete street address masked ('24, Rose Garden Street' -> [ADDRESS_1]).")

    # --------------------------------------------------------------------------
    # 11. State License Number & Non-Greedy Word Safety
    # --------------------------------------------------------------------------
    t11 = "Licence: TN-MED-2020-77891. Condition was also documented in chart."
    m11, _, _ = deid.deidentify(t11)
    assert "[LICENSE_1]" in m11, f"Failed License: {m11}"
    assert "[ZIP_1]" not in m11, f"License collided with ZIP: {m11}"
    assert "documented" in m11, f"Word corruption: 'documented' was damaged in: {m11}"
    print("[PASS] Test 11: Complete license number masked without ZIP collision; 'documented' intact.")

    # --------------------------------------------------------------------------
    # 12. Digital Identifiers (URLs, IPv4, IPv6, Emails, Phones, Faxes, SSN)
    # --------------------------------------------------------------------------
    t12 = (
        "Portal: https://kmch.tn.health.org/telehealth/v1. "
        "IPv4: 192.168.1.1. IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334. "
        "Phone: +91 9842156789 | Fax: 0422-2456789 | Email: doc@hospital.org | SSN: 123-45-6789"
    )
    m12, _, _ = deid.deidentify(t12)
    assert "[URL_1]" in m12, f"Failed URL: {m12}"
    assert "[IP_1]" in m12, f"Failed IPv4: {m12}"
    assert "[IP_2]" in m12, f"Failed IPv6: {m12}"
    assert "[PHONE_1]" in m12, f"Failed Phone: {m12}"
    assert "[FAX_1]" in m12, f"Failed Fax: {m12}"
    assert "[EMAIL_1]" in m12, f"Failed Email: {m12}"
    assert "[SSN_1]" in m12, f"Failed SSN: {m12}"
    print("[PASS] Test 12: Digital identifiers (URLs, IPv4, IPv6, Phone, Fax, Email, SSN) all masked.")

    # --------------------------------------------------------------------------
    # 13. Reversible Local Rehydration
    # --------------------------------------------------------------------------
    t13 = "Patient: Murugan Natarajan evaluated at Salem General Hospital on 10/02/2026."
    m13, map13, _ = deid.deidentify(t13)
    simulated_llm = "Patient [NAME_1] was evaluated at [FACILITY_1] on [DATE_1]."
    restored13, unexpected13 = deid.rehydrate(simulated_llm, map13)
    assert "Murugan Natarajan" in restored13, f"Patient not restored: {restored13}"
    assert "Salem General Hospital" in restored13, f"Facility not restored: {restored13}"
    assert "10/02/2026" in restored13, f"Date not restored: {restored13}"
    assert len(unexpected13) == 0, f"Unexpected placeholders flagged: {unexpected13}"
    print("[PASS] Test 13: Local bijective rehydration restores original clinical context.")

    # --------------------------------------------------------------------------
    # 14. Unexpected LLM Placeholder Handling (Flagged and never invented)
    # --------------------------------------------------------------------------
    t14_llm = "Summary: Patient [NAME_1] was given code [UNKNOWN_CODE_99]."
    restored14, unexpected14 = deid.rehydrate(t14_llm, {"[NAME_1]": "John Doe"})
    assert "[UNKNOWN_CODE_99]" in restored14, f"Unexpected placeholder modified: {restored14}"
    assert "[UNKNOWN_CODE_99]" in unexpected14, f"Unexpected placeholder not flagged: {unexpected14}"
    print("[PASS] Test 14: Unexpected LLM placeholder left masked and correctly flagged.")

    # --------------------------------------------------------------------------
    # 15. Gemini Cloud Gateway Query
    # --------------------------------------------------------------------------
    t15_masked = "Patient [NAME_1] was evaluated at [FACILITY_1] on [DATE_1] by Dr. [CLINICIAN_1]."
    res15 = llm.query(t15_masked)
    assert "response_text" in res15 and len(res15["response_text"]) > 10, "Failed Gemini response"
    print("[PASS] Test 15: Gemini Cloud gateway query completed successfully.")

    # --------------------------------------------------------------------------
    # 16. Comprehensive Clinical Note Regression Test (Andrew & Sarah Thomas Note)
    # --------------------------------------------------------------------------
    t16_note = (
        "Patient Andrew Thomas, Age 52, presented to Sunrise Medical Hospital in Tamil Nadu with acute symptoms lasting 5 days. "
        "Emergency Contact: Sarah Thomas (Wife). "
        "Andrew Thomas was admitted for observation. "
        "Later, Sarah Thomas was updated by the clinical team. "
        "Andrew Thomas responded well to treatment and was discharged after 5 days."
    )
    m16, map16, spans16 = deid.deidentify(t16_note)

    # 1. Andrew Thomas -> [NAME_1] everywhere (3 occurrences)
    assert m16.count("[NAME_1]") == 3, f"Andrew Thomas must appear 3 times as [NAME_1], got: {m16}"
    assert "Andrew Thomas" not in m16, f"Andrew Thomas leaked in: {m16}"
    assert "Andrew [NAME_1]" not in m16 and "[NAME_1] Thomas" not in m16, f"Name split into separate tokens: {m16}"

    # 2. Sarah Thomas -> [NAME_2] everywhere (2 occurrences)
    assert m16.count("[NAME_2]") == 2, f"Sarah Thomas must appear 2 times as [NAME_2], got: {m16}"
    assert "Sarah Thomas" not in m16, f"Sarah Thomas leaked in: {m16}"
    assert "Sarah [NAME_2]" not in m16 and "[NAME_2] Thomas" not in m16, f"Name split into separate tokens: {m16}"

    # 3. Sunrise Medical Hospital -> [FACILITY_1], never HEALTH_PLAN
    assert "[FACILITY_1]" in m16, f"Sunrise Medical Hospital not masked as [FACILITY_1]: {m16}"
    assert "Sunrise Medical Hospital" not in m16, f"Facility name leaked: {m16}"
    assert "[HEALTH_PLAN_1]" not in m16, f"Facility falsely categorized as HEALTH_PLAN: {m16}"
    assert map16.get("[FACILITY_1]") == "Sunrise Medical Hospital", f"Incorrect facility mapping: {map16}"

    # 4. State names preserved: Tamil Nadu & Karnataka
    assert "Tamil Nadu" in m16, f"Tamil Nadu was incorrectly masked: {m16}"
    t16_state = "Patient lives in Karnataka."
    m16_state, _, _ = deid.deidentify(t16_state)
    assert "Karnataka" in m16_state, f"Karnataka was incorrectly masked: {m16_state}"

    # 5. Age 52 and relative time '5 days' preserved
    assert "Age 52" in m16, f"Age 52 was incorrectly masked: {m16}"
    assert "5 days" in m16, f"5 days relative time was incorrectly masked: {m16}"

    print("[PASS] Test 16: Clinical regression note verified (Andrew -> [NAME_1] x3, Sarah -> [NAME_2] x2, Facility -> [FACILITY_1], Tamil Nadu & Age 52 & 5 days preserved).")

    # --------------------------------------------------------------------------
    # 17. Peter Parkinson, Clinicians & Repeated Location Regression Test
    # --------------------------------------------------------------------------
    t17_note = (
        "Patient: Peter Parkinson, Age 65, presented with tremors in Coimbatore, Tamil Nadu.\n"
        "He was diagnosed with Parkinson's disease 2 weeks ago.\n"
        "Dr. Parkinson evaluated Peter Parkinson today and advised monitoring for 7 days.\n"
        "Consultant: Dr. John Miller at the clinic in Coimbatore reviewed the plan."
    )
    m17, map17, spans17 = deid.deidentify(t17_note)

    # 1. Peter Parkinson -> [NAME_1] (never split into first/last, consistent everywhere)
    assert m17.count("[NAME_1]") == 2, f"Peter Parkinson must appear 2 times as [NAME_1], got: {m17}"
    assert "Peter Parkinson" not in m17, f"Peter Parkinson leaked in: {m17}"
    assert "Peter [NAME_1]" not in m17 and "[NAME_1] Parkinson" not in m17, f"Name split into separate placeholders: {m17}"
    assert map17.get("[NAME_1]") == "Peter Parkinson", f"Incorrect patient mapping: {map17}"

    # 2. Dr. Parkinson -> [CLINICIAN_1] and Dr. John Miller -> [CLINICIAN_2]
    assert "[CLINICIAN_1]" in m17, f"Dr. Parkinson not masked as [CLINICIAN_1]: {m17}"
    assert "Dr. Parkinson" not in m17, f"Dr. Parkinson leaked in: {m17}"
    assert "[CLINICIAN_2]" in m17, f"Dr. John Miller not masked as [CLINICIAN_2]: {m17}"
    assert "Dr. John Miller" not in m17, f"Dr. John Miller leaked in: {m17}"
    assert map17.get("[CLINICIAN_1]") == "Dr. Parkinson", f"Incorrect clinician 1 mapping: {map17}"
    assert map17.get("[CLINICIAN_2]") == "Dr. John Miller", f"Incorrect clinician 2 mapping: {map17}"

    # 3. Coimbatore -> [CITY_1] everywhere
    assert m17.count("[CITY_1]") == 2, f"Coimbatore must appear 2 times as [CITY_1], got: {m17}"
    assert "Coimbatore" not in m17, f"Coimbatore leaked in: {m17}"
    assert map17.get("[CITY_1]") == "Coimbatore", f"Incorrect city mapping: {map17}"

    # 4. Preserved entities: Parkinson's disease, Age 65, 2 weeks, 7 days, Tamil Nadu
    assert "Parkinson's disease" in m17, f"Parkinson's disease was masked in: {m17}"
    assert "Age 65" in m17, f"Age 65 was masked in: {m17}"
    assert "2 weeks" in m17, f"2 weeks was masked in: {m17}"
    assert "7 days" in m17, f"7 days was masked in: {m17}"
    assert "Tamil Nadu" in m17, f"Tamil Nadu was masked in: {m17}"

    # 5. Structure, labels, colons and spacing preserved
    assert "Patient: [NAME_1]" in m17, f"Patient label/colon damaged: {m17}"
    assert "Consultant: [CLINICIAN_2]" in m17, f"Consultant label/colon damaged: {m17}"

    print("[PASS] Test 17: Peter Parkinson regression verified (Peter -> [NAME_1] x2, Dr. Parkinson -> [CLINICIAN_1], Dr. John Miller -> [CLINICIAN_2], Coimbatore -> [CITY_1] x2, conditions & timelines preserved).")

    # --------------------------------------------------------------------------
    # 18. Identifier Classification & URL Masking Regression Test
    # --------------------------------------------------------------------------
    t18_note = (
        "Patient: Peter Parkinson, Age 65, evaluated 5 days post-surgery.\n"
        "Health Plan ID: HPI-778899-2026 (Secondary Plan: PLAN-889900).\n"
        "Billing Account: ACC-987654321 (Alt: ACC/987654321).\n"
        "Emergency Contact Phone: +91 9842156789.\n"
        "Clinical Portal: https://telehealth.kmch.org/patient/records?session=auth9982&user=clinician_1.\n"
        "Telehealth Link: [Patient Video Portal](https://telehealth.kmch.org/video/room?id=conf7788&pass=secret123).\n"
        "Patient is recovering well. Review in 2 weeks."
    )
    m18, map18, spans18 = deid.deidentify(t18_note)

    # 1. Health Plan IDs: HPI-778899-2026 and PLAN-889900
    assert "[HEALTH_PLAN_1]" in m18, f"HPI-778899-2026 not masked as [HEALTH_PLAN_1]: {m18}"
    assert "HPI-778899-2026" not in m18, f"HPI leaked in: {m18}"
    assert "[HEALTH_PLAN_2]" in m18, f"PLAN-889900 not masked as [HEALTH_PLAN_2]: {m18}"
    assert "PLAN-889900" not in m18, f"PLAN-889900 leaked in: {m18}"
    # Verify health plan is NEVER classified as phone
    assert "778899-2026" not in m18, f"HPI sub-digits leaked: {m18}"
    assert not any(s["category"] == "PHONE" and "778899" in s["entity"] for s in spans18), f"HPI misclassified as PHONE!"

    # 2. Account numbers: ACC-987654321 and slash-separated ACC/987654321
    assert "[ACCOUNT_1]" in m18, f"ACC-987654321 not masked as [ACCOUNT_1]: {m18}"
    assert "ACC-987654321" not in m18, f"ACC-987654321 leaked: {m18}"
    assert "ACC/987654321" not in m18, f"ACC/987654321 leaked: {m18}"

    # 3. URL detection: Query parameters and Markdown links
    assert "[URL_1]" in m18, f"Bare URL with query params not masked as [URL_1]: {m18}"
    assert "telehealth.kmch.org/patient/records" not in m18, f"URL path leaked: {m18}"
    assert "session=auth9982" not in m18, f"URL query param leaked: {m18}"
    assert "[URL_2]" in m18, f"Markdown URL not masked as [URL_2]: {m18}"
    assert "Patient Video Portal" not in m18, f"Markdown link text leaked: {m18}"
    assert "video/room?id=conf7788" not in m18, f"Markdown destination leaked: {m18}"

    # 4. Correct Entity Classification: Phone
    assert "[PHONE_1]" in m18, f"Phone not masked as [PHONE_1]: {m18}"
    assert "+91 9842156789" not in m18, f"Phone number leaked: {m18}"

    # 5. Preserve Clinical Text & Relative Duration
    assert "5 days post-surgery" in m18, f"Relative duration '5 days post-surgery' damaged: {m18}"
    assert "recovering well" in m18, f"Clinical text 'recovering well' damaged by MRN: {m18}"
    assert "2 weeks" in m18, f"Relative duration '2 weeks' damaged: {m18}"
    assert "Patient: [NAME_1]" in m18, f"Patient label damaged: {m18}"

    print("[PASS] Test 18: Identifier classification & URL masking regression verified (HPI -> HEALTH_PLAN, ACC -> ACCOUNT, Markdown & query URLs -> URL, Phone -> PHONE, clinical text preserved).")

    # --------------------------------------------------------------------------
    # 19. Advanced Age Generalization, Patient IDs, Gender & Room Verification
    # --------------------------------------------------------------------------
    t19_note = (
        "ADMISSION INTAKE NOTE\n"
        "Patient ID: 123456 | Alt Ref: PT-2026-778899 | Tag: PT2026778899\n"
        "Medical Record: MRN-551290 | Insurance: INS-2026-445566\n"
        "Prescription: RX-778899 | Specimen: LAB-2026-112233\n"
        "Facility Location: Room: 402, Bed: 12 (Alt: Room # 301-B)\n"
        "Demographics: Gender: Male, Patient is Age: 96 years.\n"
        "Senior history: Diagnosed when aged 96; companion is a 96-year-old retired clinician.\n"
        "Note: Roommate is 96 years old, while visiting brother is Age 89 and grandson is Age 45.\n"
        "Clinical Plan: Administer Atorvastatin 40mg daily for 5 days. Blood pressure stable at 120/80 mmHg."
    )
    m19, map19, spans19, audit19 = deid.deidentify_with_audit(t19_note)

    # 1. Age Detection and Safe Harbor Generalization (ages > 89 generalized to literal 90+, never AGE placeholder)
    assert "90+" in m19, f"90+ missing from masked text: {m19}"
    assert "[AGE_" not in m19, f"Unexpected [AGE_] placeholder found in: {m19}"
    assert "96 years" not in m19, f"Exact age 96 leaked in text: {m19}"
    assert "aged 96" not in m19, f"aged 96 leaked in text: {m19}"
    assert "96-year-old" not in m19, f"96-year-old leaked in text: {m19}"
    assert "96 years old" not in m19, f"96 years old leaked in text: {m19}"
    for k in map19.keys():
        assert "AGE" not in k, f"Age placeholder found in mapping: {k}"
    # Verify ages <= 89 preserved
    assert "Age 89" in m19, f"Age 89 was incorrectly masked: {m19}"
    assert "Age 45" in m19, f"Age 45 was incorrectly masked: {m19}"

    # 2. Patient ID & Clinical Identifier Detection
    assert "PT-2026-778899" not in m19, f"PT-2026-778899 leaked: {m19}"
    assert "PT2026778899" not in m19, f"PT2026778899 leaked: {m19}"
    assert "Patient ID: 123456" not in m19, f"Patient ID: 123456 leaked: {m19}"
    assert "Patient ID: [PATIENT_ID_" in m19, f"Patient ID label missing: {m19}"
    assert "MRN-551290" not in m19, f"MRN-551290 leaked: {m19}"
    assert "[MRN_1]" in m19, f"MRN placeholder missing: {m19}"
    assert "INS-2026-445566" not in m19, f"INS-2026-445566 leaked: {m19}"
    assert "[HEALTH_PLAN_" in m19, f"Health Plan placeholder missing: {m19}"
    assert "RX-778899" not in m19, f"RX-778899 leaked: {m19}"
    assert "[PRESCRIPTION_" in m19, f"Prescription placeholder missing: {m19}"
    assert "LAB-2026-112233" not in m19, f"LAB-2026-112233 leaked: {m19}"
    assert "[LAB_ID_" in m19, f"Lab ID placeholder missing: {m19}"

    # 3. Gender Non-Masking
    assert "Gender: Male" in m19 or "Male" in m19, f"Gender was incorrectly masked: {m19}"

    # 4. Room & Bed Detection (contextually linked, not blindly masking numbers)
    assert "Room: [ROOM_" in m19, f"Room: 402 not masked: {m19}"
    assert "402" not in m19, f"Room 402 leaked: {m19}"
    assert "Bed: [ROOM_" in m19, f"Bed: 12 not masked: {m19}"
    assert "Room # [ROOM_" in m19, f"Room # 301-B not masked: {m19}"
    assert "301-B" not in m19, f"Room 301-B leaked: {m19}"
    # Verify clinical dosages, durations and vitals are preserved
    assert "40mg" in m19, f"Dosage 40mg damaged: {m19}"
    assert "5 days" in m19, f"Duration 5 days damaged: {m19}"
    assert "120/80 mmHg" in m19, f"Blood pressure 120/80 mmHg damaged: {m19}"

    # 5. Audit Verification & Leak Detection
    assert audit19["is_safe"] is True, f"Audit flagged potential leaks: {audit19['potential_missed_phi']}"
    assert audit19["status"] == "PASS", f"Audit failed: {audit19}"
    assert len(audit19["potential_missed_phi"]) == 0, f"Potential unmasked PHI found: {audit19['potential_missed_phi']}"
    assert len(audit19["consistency_errors"]) == 0, f"Consistency errors found: {audit19['consistency_errors']}"
    assert "Zero-Leakage Confirmed" in audit19["report"], f"Report missing confirmation: {audit19['report']}"

    print("[PASS] Test 19: Advanced age Safe Harbor (90+), Patient IDs (PT/RX/LAB/INS/MRN), Gender preservation, Room masking, and Post-Masking Audit Verification confirmed.")

    # --------------------------------------------------------------------------
    # 20. Test Case 02: Full Name / Surname Propagation, Medical Condition Preservation,
    #     Clinical Labels, Facility, Mobile, Insurance, Lab ID & Heading Protection
    # --------------------------------------------------------------------------
    t20_note = (
        "Clinical Information:\n"
        "Patient: Rajesh Sharma\n"
        "Diagnosis: Chronic Gastritis, Acute Gastritis, Mild Dehydration and Diabetes Mellitus.\n"
        "Treatment: Oral Rehydration Salts and Pantoprazole.\n"
        "Vital Signs: Heart Rate: 78 bpm, Blood Pressure: 120/80 mmHg, Temperature: 98.6 F.\n"
        "Doctor's Notes:\n"
        "Patient Sharma was evaluated. Sharma tolerated oral fluids well.\n"
        "Hospital: Apollo Hospital\n"
        "Mobile: 9840123456\n"
        "Insurance ID: INS-778899\n"
        "Lab ID: LAB-2026-998811"
    )
    m20, map20, spans20, audit20 = deid.deidentify_with_audit(t20_note)

    # 1. Prevent Surname Leakage & Ensure Consistent Placeholder Reuse
    # Full name "Rajesh Sharma", "Patient Sharma", and standalone "Sharma" in doctor's notes must all be [NAME_1]
    assert "Rajesh Sharma" not in m20, f"Full name leaked: {m20}"
    assert "Sharma" not in m20.replace("[NAME_1]", ""), f"Surname leaked in text: {m20}"
    assert m20.count("[NAME_1]") == 3, f"Expected exactly 3 occurrences of [NAME_1], got {m20.count('[NAME_1]')}: {m20}"
    assert map20.get("[NAME_1]") == "Rajesh Sharma", f"Incorrect name mapping: {map20}"

    # 2. Preserve Medical Conditions
    assert "Chronic Gastritis" in m20, f"Chronic Gastritis masked: {m20}"
    assert "Acute Gastritis" in m20, f"Acute Gastritis masked: {m20}"
    assert "Mild Dehydration" in m20, f"Mild Dehydration masked: {m20}"
    assert "Diabetes Mellitus" in m20, f"Diabetes Mellitus masked: {m20}"

    # 3. Preserve Clinical Labels
    assert "Heart Rate" in m20, f"Heart Rate label masked: {m20}"
    assert "Blood Pressure" in m20, f"Blood Pressure label masked: {m20}"
    assert "Temperature" in m20, f"Temperature label masked: {m20}"
    assert "Vital Signs:" in m20, f"Vital Signs label masked: {m20}"

    # 4. Do not mask medical diagnoses, medications or treatment information
    assert "Oral Rehydration Salts" in m20, f"Oral Rehydration Salts masked: {m20}"
    assert "Pantoprazole" in m20, f"Pantoprazole masked: {m20}"

    # 5. Hospital and Healthcare Entity Detection
    assert "Apollo Hospital" not in m20, f"Hospital leaked: {m20}"
    assert "[FACILITY_1]" in m20, f"Facility placeholder missing: {m20}"
    assert map20.get("[FACILITY_1]") == "Apollo Hospital", f"Incorrect facility mapping: {map20}"

    # 6. Mobile numbers and Insurance IDs detected and masked
    assert "9840123456" not in m20, f"Mobile leaked: {m20}"
    assert "[PHONE_1]" in m20, f"Phone placeholder missing: {m20}"
    assert "INS-778899" not in m20, f"Insurance ID leaked: {m20}"
    assert "[HEALTH_PLAN_1]" in m20, f"Insurance placeholder missing: {m20}"

    # 7. Laboratory ID Detection (atomic, not split into duplicate tokens)
    assert "LAB-2026-998811" not in m20, f"Lab ID leaked: {m20}"
    assert "[LAB_ID_1]" in m20, f"Lab ID placeholder missing: {m20}"
    assert map20.get("[LAB_ID_1]") == "LAB-2026-998811", f"Lab ID mapping incorrect: {map20}"

    # 8. Preserve Section Headings
    assert "Clinical Information:" in m20, f"Clinical Information heading damaged: {m20}"
    assert "Diagnosis:" in m20, f"Diagnosis heading damaged: {m20}"
    assert "Treatment:" in m20, f"Treatment heading damaged: {m20}"
    assert "Doctor's Notes:" in m20, f"Doctor's Notes heading damaged: {m20}"

    # 9. Structure and Clinical Meaning
    assert "Patient: [NAME_1]" in m20, f"Patient structure damaged: {m20}"
    assert "Hospital: [FACILITY_1]" in m20, f"Hospital structure damaged: {m20}"
    assert "Mobile: [PHONE_1]" in m20, f"Mobile structure damaged: {m20}"
    assert "Insurance ID: [HEALTH_PLAN_1]" in m20, f"Insurance ID structure damaged: {m20}"
    assert "Lab ID: [LAB_ID_1]" in m20, f"Lab ID structure damaged: {m20}"

    # 10. Audit Verification Report
    assert audit20["is_safe"] is True, f"Audit flagged potential leaks: {audit20['potential_missed_phi']}"
    assert audit20["status"] == "PASS", f"Audit failed: {audit20}"
    assert len(audit20["potential_missed_phi"]) == 0, f"Remaining PHI detected: {audit20['potential_missed_phi']}"
    assert len(audit20["consistency_errors"]) == 0, f"Consistency errors: {audit20['consistency_errors']}"

    print("[PASS] Test 20: Test Case 02 verified (Surname propagation without leak, Gastritis/Dehydration/Diabetes conditions preserved, Vitals/Headings intact, Mobile/Insurance/Lab ID masked).")

    # --------------------------------------------------------------------------
    # 21. Test Case 03 Regression Test (Imaging IDs, Label Preservation, Atomic Lab IDs, Locality Safe Harbor, Localhost URLs/HTML & Consistent Bijective Masking)
    # --------------------------------------------------------------------------
    t21_note = (
        "# Clinical Consultation Report\n\n"
        "Clinical Information:\n"
        "Patient: Kavitha Sundaram | Age: 48 | Locality: Peelamedu, Coimbatore\n"
        "Emergency Phone: +91 9842156789 | Mobile Number: 9840123456\n"
        "Visit Date: 15/03/2026 | Next Review: 15/03/2026\n\n"
        "Diagnosis: High Cholesterol, Hypertension, Diabetes and Migraine.\n"
        "Treatment: Atorvastatin 20mg and Amlodipine 5mg.\n\n"
        "Prescription Number: RX-889911\n"
        "Lab Reference: LAB-2026-778899\n"
        "Imaging Reference: IMG-2026-776655\n\n"
        "Portal Link: http://localhost:8080/patient/view?id=kavitha99\n"
        'Patient Anchor: <a href="http://localhost:8080/portal">Patient Portal</a>\n\n'
        "### Doctor's Notes:\n"
        "Patient Kavitha Sundaram was reviewed on 15/03/2026.\n"
        "Sundaram reported mild headache. High Cholesterol is being managed well.\n"
        "Follow up in 4 weeks."
    )
    m21, map21, spans21 = deid.deidentify(t21_note)
    audit21 = deid.audit_verification(t21_note, m21, map21, spans21)

    # 1. Imaging study/report identifier detected and masked
    assert "IMG-2026-776655" not in m21, f"Imaging ID leaked in: {m21}"
    assert "[IMAGING_ID_1]" in m21, f"Imaging ID placeholder missing: {m21}"
    assert map21.get("[IMAGING_ID_1]") == "IMG-2026-776655", f"Incorrect imaging ID mapping: {map21}"

    # 2. Preserve medical conditions
    assert "High Cholesterol" in m21, f"High Cholesterol masked: {m21}"
    assert "Hypertension" in m21, f"Hypertension masked: {m21}"
    assert "Diabetes" in m21, f"Diabetes masked: {m21}"
    assert "Migraine" in m21, f"Migraine masked: {m21}"

    # 3. Preserve normal field labels (mask ONLY values, not labels)
    assert "Mobile Number: [PHONE_2]" in m21, f"Mobile Number label damaged: {m21}"
    assert "Emergency Phone: [PHONE_1]" in m21, f"Emergency Phone label damaged: {m21}"
    assert "Prescription Number: [PRESCRIPTION_1]" in m21, f"Prescription Number label damaged: {m21}"
    assert "Lab Reference: [LAB_ID_1]" in m21, f"Lab Reference label damaged: {m21}"
    assert "Imaging Reference: [IMAGING_ID_1]" in m21, f"Imaging Reference label damaged: {m21}"
    assert "Portal Link: [URL_1]" in m21, f"Portal Link label damaged: {m21}"
    assert "Patient Anchor: [URL_2]" in m21, f"Patient Anchor label damaged: {m21}"

    # 4. Atomic Laboratory ID detection without splitting or duplicate tokens
    assert "LAB-2026-778899" not in m21, f"Lab ID leaked in: {m21}"
    assert "[LAB_ID_1]" in m21, f"Lab ID placeholder missing: {m21}"
    assert map21.get("[LAB_ID_1]") == "LAB-2026-778899", f"Incorrect lab ID mapping: {map21}"

    # 5. Locality and neighborhood detection under HIPAA geographic policy
    assert "Peelamedu" not in m21, f"Peelamedu leaked in: {m21}"
    assert "Coimbatore" not in m21, f"Coimbatore leaked in: {m21}"
    assert "[CITY_1]" in m21 and "[CITY_2]" in m21, f"Locality placeholders missing: {m21}"
    assert map21.get("[CITY_1]") == "Peelamedu", f"Incorrect city 1 mapping: {map21}"
    assert map21.get("[CITY_2]") == "Coimbatore", f"Incorrect city 2 mapping: {map21}"

    # 6. Localhost URLs and HTML anchor tags cleanly masked without malformed output
    assert "http://localhost:8080/patient/view?id=kavitha99" not in m21, f"Localhost URL leaked: {m21}"
    assert "kavitha99" not in m21, f"Patient parameter leaked in URL: {m21}"
    assert '<a href="http://localhost:8080/portal">Patient Portal</a>' not in m21, f"Anchor tag leaked: {m21}"
    assert "[URL_1]" in m21 and "[URL_2]" in m21, f"URL placeholders missing: {m21}"

    # 7. Preserved headings, document formatting, and relative time
    assert "# Clinical Consultation Report" in m21, f"Report heading damaged: {m21}"
    assert "### Doctor's Notes:" in m21, f"Doctor's Notes heading damaged: {m21}"
    assert "Age: 48" in m21, f"Age <= 89 was masked: {m21}"
    assert "4 weeks" in m21, f"Relative timeline damaged: {m21}"

    # 8. Consistent bijective person and date masking
    assert "Kavitha Sundaram" not in m21, f"Full patient name leaked: {m21}"
    assert "Sundaram" not in m21.replace("[NAME_1]", ""), f"Surname leaked in notes: {m21}"
    assert m21.count("[NAME_1]") == 3, f"Expected 3 occurrences of [NAME_1], got {m21.count('[NAME_1]')}: {m21}"
    assert "15/03/2026" not in m21, f"Visit date leaked: {m21}"
    assert m21.count("[DATE_1]") == 3, f"Expected 3 occurrences of [DATE_1], got {m21.count('[DATE_1]')}: {m21}"

    # 9. Audit Verification Report (100% clean scan)
    assert audit21["is_safe"] is True, f"Audit flagged potential leaks: {audit21['potential_missed_phi']}"
    assert audit21["status"] == "PASS", f"Audit failed: {audit21}"
    assert len(audit21["potential_missed_phi"]) == 0, f"Remaining PHI detected: {audit21['potential_missed_phi']}"
    assert len(audit21["consistency_errors"]) == 0, f"Consistency errors: {audit21['consistency_errors']}"

    print("[PASS] Test 21: Test Case 03 verified (Imaging ID masked, Conditions & Field labels preserved, Atomic Lab ID, Locality masked, Localhost URL/HTML safe, Markdown headings intact).")

    # --------------------------------------------------------------------------
    # 22. Strict Age Handling Rules (Rules 1-7: numeric/word 90+, DOB vs Age, spacing/labels, consistency)
    # --------------------------------------------------------------------------
    t22_note = (
        "# Geriatric Clinical Review Note\n\n"
        "Patient Information:\n"
        "Patient: Margaret Holloway | Age: 96 years | Gender: Female\n"
        "DOB: 10/12/1932 | Locality: Peelamedu, Coimbatore\n\n"
        "Clinical Observation:\n"
        "Margaret Holloway is a nonagenarian who was diagnosed when aged ninety.\n"
        "Her roommate is ninety-six years old, and senior companion is 102 years old.\n"
        "Retired clinician friend is a ninety-six-year-old centenarian advocate.\n"
        "Visiting daughter is Age 64 and grandson is Age 28.\n"
        "DOB of daughter: 15/04/1962 (Age: 64).\n"
        "Note: Patient was admitted for 7 days post-op with stable vitals."
    )
    m22, map22, spans22, audit22 = deid.deidentify_with_audit(t22_note)

    # Rule 1 & 2: Numeric & word formats >= 90 replaced with literal 90+, never an AGE placeholder
    assert "Age: 90+ years" in m22, f"Age: 96 years not replaced: {m22}"
    assert "aged 90+" in m22, f"aged ninety not replaced: {m22}"
    assert "90+ years old" in m22, f"ninety-six years old not replaced: {m22}"
    assert "90+-year-old" in m22, f"ninety-six-year-old not replaced: {m22}"
    assert "is 90+ years old" in m22, f"102 years old not replaced: {m22}"
    assert "is a 90+" in m22, f"nonagenarian not replaced: {m22}"
    assert "[AGE_" not in m22, f"Found unexpected [AGE_] placeholder in: {m22}"
    for k in map22.keys():
        assert "AGE" not in k, f"Found AGE placeholder in mapping: {k}"

    # Rule 3: Ages below 90 preserved under Safe Harbor
    assert "Age 64" in m22, f"Age 64 was incorrectly masked: {m22}"
    assert "Age 28" in m22, f"Age 28 was incorrectly masked: {m22}"
    assert "Age: 64" in m22, f"Age: 64 was incorrectly masked: {m22}"

    # Rule 4: Never confuse age with date of birth (DOBs masked as [DATE_n])
    assert "10/12/1932" not in m22, f"DOB leaked: {m22}"
    assert "15/04/1962" not in m22, f"DOB leaked: {m22}"
    assert "[DATE_1]" in m22, f"Date placeholder missing: {m22}"

    # Rule 5: Preserve original document structure, labels, colons and spacing
    assert "Age: 90+ years" in m22, f"Spacing or label damaged: {m22}"
    assert "# Geriatric Clinical Review Note" in m22, f"Heading damaged: {m22}"
    assert "Patient Information:" in m22, f"Section label damaged: {m22}"
    assert "7 days" in m22, f"Relative duration damaged: {m22}"

    # Rule 6: Never create PHI placeholders for non-existent information
    for pl, orig in map22.items():
        assert orig in t22_note, f"Placeholder {pl} maps to non-existent text: {orig}"

    # Rule 7: Consistent placeholders for repeated PHI values
    assert "Margaret Holloway" not in m22, f"Patient name leaked: {m22}"
    assert m22.count("[NAME_1]") == 2, f"Expected 2 occurrences of [NAME_1], got {m22.count('[NAME_1]')}: {m22}"

    # Audit Status
    assert audit22["is_safe"] is True, f"Audit flagged potential leaks: {audit22['potential_missed_phi']}"
    assert audit22["status"] == "PASS", f"Audit failed: {audit22}"
    print("[PASS] Test 22: Strict Age Handling Rules (Rules 1-7: numeric/word 90+, DOB vs Age, spacing/labels, consistency, zero-leakage audit).")

    # --------------------------------------------------------------------------
    # 23. Patient Clinical Assessment Report (Michael Rajesh Kumar)
    # --------------------------------------------------------------------------
    t23_note = (
        "# PATIENT CLINICAL ASSESSMENT REPORT\n\n"
        "**Patient Information**\n\n"
        "Patient Name: Michael Rajesh Kumar  \n"
        "Age: 67 years  \n"
        "Date of Birth: 14/09/1959  \n"
        "Gender: Male  \n"
        "Patient ID: HSP-2026-458921  \n"
        "Medical Record Number: MRN-78945623  \n\n"
        "**Contact Information**\n\n"
        "Residential Address: Flat 302, Green Park Apartments, Anna Nagar, Chennai, Tamil Nadu - 600040.\n\n"
        "Mobile Number: +91 98765 43210  \n"
        "Alternate Contact: +91 87654 32109  \n"
        "Email Address: michael.kumar@gmail.com  \n\n"
        "**Clinical Details**\n\n"
        "Mr. Michael Rajesh Kumar visited Royal Care Hospital, Coimbatore, on 20 November 2026, complaining of persistent headaches and dizziness.\n\n"
        "He was examined by Dr. Priya Sharma (Registration No: TN-MED-45678).\n\n"
        "His wife, Anitha Kumar, accompanied him during the consultation. For further communication, she can be reached at 9988776655.\n\n"
        "**Insurance Information**\n\n"
        "Insurance Provider: Star Health Insurance  \n"
        "Policy Number: SH-2026-987654321  \n"
        "Insurance Member ID: MEM-456789123  \n\n"
        "**Treatment Plan**\n\n"
        "The patient was advised to undergo a blood test and return for a follow-up consultation after seven days."
    )
    m23, map23, spans23, audit23 = deid.deidentify_with_audit(t23_note)

    assert "Michael Rajesh Kumar" not in m23, f"Patient name leaked: {m23}"
    assert m23.count("[NAME_1]") == 2, f"Expected 2 occurrences of [NAME_1], got: {m23}"
    assert "Age: 67 years" in m23, f"Age 67 must be preserved under Safe Harbor: {m23}"
    assert "Gender: Male" in m23, f"Gender Male must be preserved: {m23}"
    assert "14/09/1959" not in m23, f"DOB leaked: {m23}"
    assert "[DATE_1]" in m23, f"DOB placeholder missing: {m23}"
    assert "HSP-2026-458921" not in m23 and "[PATIENT_ID_1]" in m23, f"Patient ID issue: {m23}"
    assert "MRN-78945623" not in m23 and "[MRN_1]" in m23, f"MRN issue: {m23}"
    assert "Flat 302, Green Park Apartments" not in m23 and "[ADDRESS_1]" in m23, f"Address issue: {m23}"
    assert "Anna Nagar" not in m23 and "Chennai" not in m23 and "Coimbatore" not in m23, f"Cities leaked: {m23}"
    assert "Tamil Nadu" in m23, f"State Tamil Nadu must be preserved under Safe Harbor: {m23}"
    assert "600040" not in m23 and "[ZIP_1]" in m23, f"ZIP leaked: {m23}"
    assert "+91 98765 43210" not in m23 and "+91 87654 32109" not in m23 and "9988776655" not in m23, f"Phone leaked: {m23}"
    assert "michael.kumar@gmail.com" not in m23 and "[EMAIL_1]" in m23, f"Email leaked: {m23}"
    assert "Royal Care Hospital" not in m23 and "[FACILITY_1]" in m23, f"Facility leaked: {m23}"
    assert "20 November 2026" not in m23 and "[DATE_2]" in m23, f"Visit date leaked: {m23}"
    assert "Dr. Priya Sharma" not in m23 and "[CLINICIAN_1]" in m23, f"Clinician leaked: {m23}"
    assert "TN-MED-45678" not in m23 and "[LICENSE_1]" in m23, f"License leaked: {m23}"
    assert "Anitha Kumar" not in m23 and "[NAME_2]" in m23, f"Wife leaked: {m23}"
    assert "Star Health Insurance" not in m23 and "[HEALTH_PLAN_1]" in m23, f"Health Plan provider leaked: {m23}"
    assert "SH-2026-987654321" not in m23 and "[HEALTH_PLAN_2]" in m23, f"Policy number leaked: {m23}"
    assert "MEM-456789123" not in m23 and "[HEALTH_PLAN_3]" in m23, f"Member ID leaked: {m23}"
    assert "blood test" in m23 and "follow-up consultation after seven days" in m23, f"Clinical plan damaged: {m23}"
    assert audit23["is_safe"] is True, f"Audit failed: {audit23}"

    # Verify Bijective Rehydration
    restored23, unexp23 = deid.rehydrate(m23, map23)
    assert restored23 == t23_note, "Rehydrated text did not match original note exactly!"
    print("[PASS] Test 23: Patient Clinical Assessment Report (Michael Rajesh Kumar) 100% de-identified, verified, and bijectively restored.")

    print("=" * 80)
    print("VERIFICATION SUMMARY: ALL AUDIT TESTS PASSED (100% SUCCESS RATE)")
    print("=" * 80)

if __name__ == "__main__":
    run_tests()
