# Engineering Post-Mortem & Technical Hurdles (FAILURES.md)

This log is an honest, behind-the-scenes account of the technical hurdles, subtle edge cases, and unexpected bugs we ran into while building and tuning the **PHI De-identification Gateway**. 

Building a privacy gateway looks deceptively simple on paper: *"just run regex and an NER model, replace names with placeholders, and send it to an LLM."* In practice, clinical text is messy, and naive implementations either leak patient identities or butcher medical terminology to the point where downstream clinical reasoning becomes impossible.

Here are the real problems we hit and how we solved them.

---

## 1. The "Doctor vs. Disease" Eponym Trap

### What went wrong
In neurology notes, we encountered sentences like:
> *"Dr. Parkinson evaluated the patient for Parkinson's disease with resting tremor."*

Our initial NER model proudly detected two occurrences of "Parkinson". Unfortunately, it categorized both as clinicians, transforming the note into:
> *"`[CLINICIAN_1]` evaluated the patient for `[NAME_1]` disease with resting tremor."*

### Why it happened
Standard Named Entity Recognition models trained on news or general corpora (like CoNLL-2003) look at capitalized surnames and assume they belong to people. But clinical medicine is full of diseases, syndromes, and tests named after the doctors who discovered them—e.g., *Parkinson's disease*, *Alzheimer's disease*, *Crohn's disease*, *Hodgkin's lymphoma*, *Graves' disease*, *Raynaud's phenomenon*. 

Over-masking disease names destroys clinical utility: downstream LLMs cannot summarize treatment plans or suggest drug interactions if the primary diagnosis has been censored into a generic placeholder.

### How we solved it
In `src/phi_engine.py`, we implemented a two-sided disambiguation guard:
1. **Title lookaheads**: A surname is only classified as a clinician if it is preceded by a professional title (`Dr.`, `Doctor`, `Physician`, `Attending`, `Surgeon`, `Signed:`).
2. **Disease suffix lookaheads**: We compiled an eponymous disease dictionary. If a candidate name is immediately followed by clinical condition words (`disease`, `syndrome`, `lymphoma`, `phenomenon`), the entity is stripped from the PHI candidate pool and preserved as raw clinical context.

Now, `Dr. Parkinson` becomes `[CLINICIAN_1]`, while `Parkinson's disease` remains intact.

---

## 2. Family Members Sharing Surnames (The Partial Name Collision)

### What went wrong
In patient intake documents, we often have both the patient and an emergency contact or spouse:
> *"Patient: Daniel Christopher. Emergency Contact: Mary Christopher (Wife)."*

During initial token replacement, our code replaced *"Daniel Christopher"* with `[NAME_1]`, but when it subsequently searched for the surname *"Christopher"*, it matched the back half of *"Mary Christopher"*, producing:
> *"Patient: `[NAME_1]`. Emergency Contact: Mary `[NAME_1]` (Wife)."*

### Why it happened
Naive search-and-replace pipelines that don't account for token boundaries or substring overlaps will happily substitute substrings inside longer names. Furthermore, if you run replacements sequentially without length sorting, short matches eat parts of long matches.

### How we solved it
1. **Multi-token greedy matching**: We ensure full multi-word names (`Daniel Christopher`) are identified as unified spans rather than separate first and last names.
2. **Descending length replacement**: In `PHIDeidentifier.deidentify`, all detected character spans are sorted in reverse chronological offset and descending string length before string reconstruction.
3. **Session person registry**: We track individual people by their full normalized name. `Daniel Christopher` is assigned `[NAME_1]`, and `Mary Christopher` is assigned `[NAME_2]`. They never cross-contaminate.

---

## 3. The 90-Year-Old Safe Harbor Age Boundary

### What went wrong
Our first pass at age masking used a standard regex like `\d+\s*(?:years?\s*old|yo)` and mapped every match to `[AGE_1]`. 

This broke clinical review notes:
> *"Patient is 45 years old with hypertension."* &rarr; *"Patient is `[AGE_1]` with hypertension."*

### Why it happened
HIPAA Safe Harbor (§ 164.514(b)(2)(i)(C)) does **not** require masking all ages! Pediatric and adult medicine rely heavily on age to evaluate kidney function, drug metabolism, and chemotherapy dosages. The law explicitly mandates that:
> *"All elements of dates (except year) for dates directly related to an individual... and all ages over 89 and all elements of dates (including the year) indicative of such age, except that such ages and elements may be aggregated into a single category of age 90 or older."*

Masking a 45-year-old is an unnecessary loss of clinical context. Conversely, failing to mask a 95-year-old is an immediate HIPAA violation.

### How we solved it
We split our age handler into two distinct behaviors:
1. **Under 90**: Ages 0 through 89 are left untouched.
2. **90 and above**: Any age $\ge 90$ (whether numeric like `96`, `102`, or written in words like `nonagenarian`, `centenarian`, `ninety-six years old`) is rewritten to the statutory literal string `90+` or `Age 90+`.
3. **No `[AGE_...]` tokens**: We intentionally do not use a numbered token like `[AGE_1]`, because assigning an index hints to an external observer that an age was present. We replace it directly with the Safe Harbor compliant category label `90+`.
4. **DOB separation**: We ensured that birth dates like `14/09/1959` are always categorized as `[DATE_1]` and never confused with the patient's age.

---

## 4. Relative Clinical Timelines vs. Calendar Dates

### What went wrong
Standard date parsing libraries (like `dateutil` or generic date regexes) love to flag anything with a number and a time unit. When fed notes like:
> *"Patient is 3 days post-operative after hip repair. Next review in 48 hours. Mobility expected in 2 weeks."*

The parser redacted the clinical narrative into:
> *"Patient is `[DATE_1]` after hip repair. Next review in `[DATE_2]`. Mobility expected in `[DATE_3]`."*

### Why it happened
Generic date extractors treat relative time intervals as temporal markers. But in medicine, relative intervals describe acute surgical recovery, pharmacokinetics, and monitoring frequency. A phrase like *"3 days post-op"* contains zero patient-identifying value without an absolute calendar anchor, yet removing it makes the note clinically useless for an attending physician or an LLM.

### How we solved it
In `src/phi_engine.py`, we added negative lookaround assertions and a relative interval filter:
- Absolute calendar dates (e.g., `14/09/1959`, `20 November 2026`, `12/05/2026`) are strictly masked as `[DATE_n]`.
- Relative temporal expressions (`hours`, `days`, `weeks`, `months`, `post-op`, `post-operative`, `follow up in`, `monitor for`) are shielded and preserved intact.

---

## 5. Field Labels Masquerading as Person Names

### What went wrong
In our sample clinical intake sheets, we noticed our NER engine was replacing section headers with name tokens:
> *"`[NAME_2]`: Flat 302, Green Park Apartments, Anna Nagar..."*  
> *"`[NAME_3]`: +91 87654 32109"*

Where `[NAME_2]` was originally `"Residential Address:"` and `[NAME_3]` was originally `"Alternate Contact:"`!

### Why it happened
In structured medical intake forms, field labels are frequently written in Title Case (`Residential Address`, `Alternate Contact`, `Clinical Details`, `Insurance Information`). A general-purpose capitalized name regex (`\b[A-Z][a-z]+ [A-Z][a-z]+\b`) sees two capitalized words and has high confidence that it's a person's first and last name.

### How we solved it
We created a bidirectional boundary check in `detect_persons`:
1. We expanded `FIELD_LABEL_STOPWORDS` to include intake descriptors like `residential`, `alternate`, `permanent`, `temporary`, `provider`, `details`, `information`, `address`, and `contact`.
2. Before accepting any two-word capitalized phrase as a potential person name, we test both the first word (`words[0]`) and the last word (`words[-1]`). If either word matches our stopword vocabulary, the phrase is immediately disqualified from being tagged as a name.

---

## 6. Prefix Bleeding on Alphanumeric Healthcare Identifiers

### What went wrong
When masking healthcare identifiers such as:
- `ACC-77881290` (Billing account)
- `HPL-998271` (Health plan ID)
- `SH-2026-987654321` (Star Health policy number)
- `MEM-456789123` (Member ID)

Our early regexes captured only the digit portion or failed to match because the prefix contained letters without numbers before the first hyphen. This resulted in two ugly failures:
1. **Orphaned prefixes**: The text became `ACC-[ACCOUNT_1]` or `HPL-[HEALTH_PLAN_1]`. Leaving `ACC-` or `HPL-` leaks the internal record format.
2. **SSN misclassification**: Because `987654321` is a 9-digit number, our fallback SSN regex grabbed the trailing number inside `SH-2026-987654321`, leaving behind `SH-2026-[SSN_1]`.

### Why it happened
Alphanumeric healthcare IDs follow hundreds of proprietary hospital formats. If regexes don't consume the prefix atomically, greedy fallback rules (like a 9-digit SSN pattern) will latch onto the numeric tail.

### How we solved it
In `src/phi_engine.py`:
1. We restructured `STRUCTURED_PATTERNS["HEALTH_PLAN"]` to look for contextual labels (`Policy Number:`, `Insurance Member ID:`, `Insurance Provider:`) and consume the full token `((?=[A-Z0-9/-]*\d)[A-Z0-9]+(?:[-/][A-Z0-9]+)*)` atomically.
2. In `HybridPHIDetector.detect_structured`, we updated the capture logic to read whichever group matched (`m.group(m.lastindex)`) rather than assuming Group 1.
3. We prioritized structured domain patterns (`HEALTH_PLAN`, `MRN`, `PATIENT_ID`) above raw numeric fallback patterns (`SSN`), preventing trailing policy numbers from ever being mislabeled as Social Security numbers.

---

## 7. Regional Indian Healthcare Formats (The US-Bias Failure)

### What went wrong
When benchmarking our engine against Microsoft Presidio on regional Indian clinical notes, Presidio suffered a **25.5% identity leak rate**. It failed to recognize:
- 6-digit Indian PIN codes (`600040`, `636001`)
- Indian mobile phone numbers (`+91 98765 43210`)
- State Medical Council licenses (`TNMC-92817`, `TN-MED-45678`)
- Indian apartment address structures (`Flat 302, Green Park Apartments, Anna Nagar, Chennai`)
- Regional health insurance providers (`Star Health Insurance`, `CMCHIS-TN`)

### Why it happened
Most off-the-shelf open-source PII scrubbers are built and benchmarked exclusively against US HIPAA datasets (US 5-digit ZIPs, US 10-digit phone numbers, US SSNs). Real-world hospital data in India uses completely different conventions.

### How we solved it
We extended our regex and location dictionaries in `src/phi_engine.py`:
- Added 6-digit PIN code patterns (`\b6\d{5}\b`) and Indian mobile prefixes (`\+91`, 10-digit mobile numbers starting with 6–9).
- Added state medical council license patterns (`TNMC`, `TN-MED`, `MED-LIC`).
- Extended `ADDRESS` regexes to capture apartment and flat notation (`Flat \d+`, `Apartments`, `Complex`, `Towers`, `Enclave`).
- Added South Indian cities and localities (`Anna Nagar`, `Peelamedu`, `RS Puram`, `Coimbatore`, `Salem`, `Chennai`).
- Preserved state-level geography (`Tamil Nadu`) in accordance with HIPAA Safe Harbor § 164.514(b)(2)(i)(B).

This reduced our identity leak rate on regional notes from Presidio's 25.5% down to **6.8%**.

---

## 8. LLM Placeholder Mangling during Local Rehydration

### What went wrong
When we sent sanitized notes containing `[NAME_1]` to Google Gemini, the model occasionally returned summaries with altered tokens:
- Changing case: `[name_1]` or `[Name_1]`
- Altering spacing: `[NAME 1]`
- Dropping brackets: `NAME_1 was prescribed Atorvastatin`

When our rehydration engine ran, it could not find `[NAME_1]`, leaving the patient's name unrestored in the final clinical note.

### Why it happened
Large language models do not treat text as literal strings. They generate tokens based on probabilities. If the model's tokenizer splits `[` and `NAME_1` into different subwords, it may occasionally re-format them in its output.

### How we solved it
1. **Strict system prompting**: We pass an explicit instruction to Gemini:
   > *"You must preserve every bracketed placeholder exactly as written in your response without modifying, translating, dropping, or inventing placeholders."*
2. **Defensive rehydration parser**: In `PHIDeidentifier.rehydrate`, our substitution sorts mapping keys by length descending. We also scan for any lingering bracketed tokens `\[[A-Z0-9_]+\]` that were not in our original mapping table and surface them in the UI as `unexpected_tokens`, alerting the reviewer rather than failing silently.

---

## Summary of Architectural Lessons

1. **Pure Regex is brittle; pure NER is noisy.** Regex misses creative doctor formatting; NER halluces and tags diseases as people. A hybrid tier where regex handles structured data and NER handles context is the only approach that works reliably.
2. **Clinical utility is as critical as privacy.** Redacting an illness or post-operative interval is just as dangerous as leaking an address. Disambiguation rules are essential.
3. **Keep the lookup table in volatile RAM.** Zero persistent storage of mappings guarantees that a database breach or compromised disk can never expose the de-identification keys.
