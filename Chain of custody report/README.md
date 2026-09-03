# Digital Forensics Chain of Custody Report Generator

An interactive, premium web application designed for digital forensics examiners and incident responders. It facilitates evidence acquisition, tracking, cryptographic hash verification, and the generation of court-admissible forensic reports in compliance with ISO/IEC 27037:2012 and NIST SP 800-86 standards.

This repository implements the requirements shown in the **Digital Forensics & Incident Response** training curriculum.

---

## 🚀 Key Features

1. **Active Forensic Evidence Inventory**: Real-time listing of seized digital storage devices (HDDs, USBs, memory chips) with detailed physical description, serial numbers, acquisition times, and custody status.
2. **In-Browser Hashing Engine**: Cryptographic SHA-256 and SHA-1 hashing calculated completely locally via browser Web Crypto APIs. Supports dragging and dropping files or selecting them via explorer.
3. **Chain of Custody Transfer Ledger**: Implements chronological audit trails tracking evidence hand-offs between investigators, secured lockers, and analysis labs, with digital signatures.
4. **Court-Admissible Report Generator**: Renders a print-ready document template following strict legal forensic reporting standards. Features configurable metadata syncing and a CSS print stylesheet to generate PDF prints.
5. **Interactive Standards Guide**: Educational workflow checklist detailing steps for scene containment, write-blocked acquisitions, and secure archiving.

---

## 📝 Code Generation Prompt

If you want to recreate or expand this application, the following prompt can be used:

```text
Develop a premium, high-fidelity single-page web application (SPA) themed around a Digital Forensics Laboratory (dark mode, glassmorphism card UI, deep slate colors with electric cyan and emerald accents).

The application must implement a "Chain of Custody and Forensic Report Generator" featuring:
1. A Responsive Sidebar: Navigation tabs for Dashboard, Evidence Register, Custody Ledger, Integrity Verifier, Report Generator, and Standards Guide.
2. Case State Management: Persist case information (Case ID, Examiner, Suspect, Incident Date), evidence lists (Item #, description, acquisition source, date, hash), and custody movements in localStorage. Include option to load rich mock case data.
3. Cryptographic Hashing: Implement native Web Crypto API hashing (SHA-256 / SHA-1) so that users can drag-and-drop or select local files to compute original/verification hashes.
4. Chronological Ledger: Transfer log form to record custody hand-offs (from custodian, to custodian, date, purpose, location) with signed certification check.
5. Court Report Layout: A print-friendly workspace displaying a white paper document styled as an official court report. Include a print override stylesheet (@media print) to isolate the document for PDF export.
6. Educational Guide: Interactive checklists tracking NIST SP 800-86 and ISO/IEC 27037 compliance.
```

---

## 💻 Tech Stack
- **Structure**: Semantic HTML5
- **Style**: Custom Vanilla CSS3 (Dark themed dashboard + Light themed print paper styles)
- **Logic**: Vanilla ES6+ JavaScript (Web Crypto API for in-browser file hashing, localStorage for persistence, JSON import/export utilities)

---

## ⚙️ How to Run
1. Clone or download this folder to your local machine.
2. Open `index.html` in any modern web browser (Chrome, Edge, Firefox, or Safari).
3. The dashboard will automatically initialize with a default mock case (*DFIR-2026-9982*) so you can test features immediately.

---

## ⚖️ Conclusion: Why This Mirrors Real Casework

In digital forensics, **hashing and document integrity are absolute**. 
- **Mathematical Immutability**: By calculating hashes immediately upon collection, we establish a cryptographic fingerprint. The **Integrity Verifier** tab shows that even a single-bit alteration in an evidentiary file triggers a hash mismatch, rendering evidence inadmissible.
- **Unbroken Audit Trail**: If an investigator transfers a hard drive to a lab technician without documenting it, the defense can claim the evidence was contaminated. The **Chronological Transfer Ledger** ensures every second of custody is accounted for.
- **Compliance Alignment**: By connecting the checklists to NIST and ISO guidelines, the examiner proves to courts that standard acquisition procedures (e.g., using write-blockers and Faraday bags) were followed.
