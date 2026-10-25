# Quantum-Inspired Cyber Threat Detection for Digital Signature Security

A professional, full-stack cybersecurity web application that integrates deterministic **RSA-PSS digital signature verification** with a classical **quantum-inspired amplitude threat detection engine** and **scikit-learn Isolation Forest** anomaly detection.

Developed in Python 3.11+ using Flask, SQLAlchemy (SQLite), Python `cryptography`, and Chart.js.

---

## 1. System Architecture Overview

```
                                      +-----------------------------------------------+
                                      |            Client Web Application             |
                                      |   (Vanilla JS + CSS3 Cyber Navy Theme +       |
                                      |             Local Chart.js UMD)               |
                                      +-----------------------+-----------------------+
                                                              | HTTP / REST (CSRF-Guarded)
                                                              v
                                      +-----------------------------------------------+
                                      |                Flask App Factory              |
                                      |     (Session Security + Blueprints + CSRF)    |
                                      +-------+-----------------------+---------------+
                                              |                       |
                     +------------------------+                       +------------------------+
                     v                                                                         v
      +------------------------------+                                          +------------------------------+
      |     Cryptographic Engine     |                                          |   Quantum Threat Engine      |
      |   (Python 'cryptography')    |                                          |      (NumPy + Sklearn)       |
      |                              |                                          |                              |
      | • RSA-PSS (SHA-256 + MGF1)   |                                          | • Phase Angle Mapping \theta_j|
      | • SubjectPublicKeyInfo PEM   |                                          | • Superposition |\psi\rangle |
      | • Max Salt Length Padding    |                                          | • Born-Rule Amplitude P(Threat)|
      | • 2048/3072/4096-bit Keys    |                                          | • Isolation Forest Benchmark |
      +--------------+---------------+                                          +--------------+---------------+
                     |                                                                         |
                     +------------------------+                       +------------------------+
                                              |                       |
                                              v                       v
                                      +-----------------------------------------------+
                                      |           SQLite Database (SQLAlchemy)        |
                                      | • users (Analyst credentials & roles)         |
                                      | • verification_records (Hashes & Amplitudes)  |
                                      | • security_events (Audit trail & Bursts)      |
                                      +-----------------------------------------------+
```

---

## 2. Theoretical Mathematical Formulation

### A. The Separation of Cryptographic Proof vs. Threat Heuristics
- **Cryptographic Verification**: A purely deterministic mathematical test. If $\text{Verify}(pk, m, \sigma) = \text{True}$, the message matches the digest signed by the corresponding private key. If $\text{False}$, mathematical integrity has failed.
- **Quantum-Inspired Anomaly Scoring**: Classical digital signatures provide no insight into whether a signature failure is an isolated typographical error or an active automated dictionary attack. The quantum-inspired engine calculates an **operational threat score** to assist security operations center (SOC) analysts.
- **Academic Disclaimer**: This algorithm runs entirely on **classical CPU hardware** using NumPy. It employs mathematical concepts inspired by quantum mechanics (state superposition and probability amplitude projection), but does **not** run on quantum hardware and is **not** a post-quantum cryptographic algorithm (PQC).

### B. Amplitude Mapping and the Born Rule
1. **Feature Normalization**: Five security indicators are mapped into bounded values $x_j \in [0.0, 1.0]$:
   - $x_1$: Cryptographic verification outcome (0.0 if valid, 1.0 if invalid)
   - $x_2$: Rolling failure burst velocity: $\tanh(k / 2.5)$ across a 10-minute window
   - $x_3$: Request frequency anomaly: $\text{clip}\left(\frac{f - 2.0}{28.0}, 0.0, 1.0\right)$
   - $x_4$: Key modulus degradation ($2048\text{-bit} = 0.0$, $1024\text{-bit} = 0.6$, $<1024\text{-bit} = 1.0$)
   - $x_5$: Encoding and entropy irregularity penalty: $\text{clip}(\text{issues} \times 0.5, 0.0, 1.0)$

2. **Phase Angle Mapping**:
   $$\theta_j = x_j \cdot \frac{\pi}{2}, \quad \theta_j \in [0, \pi/2]$$

3. **Superposition State Representation**:
   $$|\psi\rangle = \alpha |0\rangle + \beta |1\rangle$$
   where $|0\rangle$ denotes the **Nominal Security State**, and $|1\rangle$ denotes the **Threat State**.
   Given domain weights $w_j \ge 0$ ($\sum_{j=1}^5 w_j = 1.0$):
   $$\beta = \sqrt{\sum_{j=1}^5 w_j \sin^2(\theta_j)}, \quad \alpha = \sqrt{1 - \beta^2}$$
   Notice that $|\alpha|^2 + |\beta|^2 = 1.0$ (satisfying the quantum Born rule normalization).

4. **Threat Probability & Operational Score**:
   $$P(\text{Threat}) = |\langle 1 | \psi \rangle|^2 = \beta^2 = \sum_{j=1}^5 w_j \sin^2\left(x_j \cdot \frac{\pi}{2}\right)$$
   $$\text{Threat Score} = 100.0 \times P(\text{Threat}) \in [0.0, 100.0]$$

5. **Severity Classification**:
   - `LOW` (0.0 – 25.0): Normal baseline operations.
   - `MEDIUM` (25.1 – 55.0): Minor deviations (e.g. low-frequency retries or non-standard key modulus).
   - `HIGH` (55.1 – 80.0): Confirmed signature mismatch or elevated burst frequency.
   - `CRITICAL` (80.1 – 100.0): Active dictionary probing, rapid repeated failures, or severe format tampering.

---

## 3. Technology Stack

- **Backend**: Python 3.11+, Flask 3.0.3, Flask-SQLAlchemy 3.1.1
- **Database**: SQLite 3 with SQLAlchemy ORM
- **Cryptography**: Python `cryptography` library (RSA, PSS padding, SHA-256)
- **Machine Learning**: `scikit-learn` 1.9.0 (Isolation Forest), `NumPy` 2.4.6
- **Frontend**: HTML5, CSS3, vanilla JavaScript, Chart.js 4.4.2 (local offline UMD bundle)
- **Testing**: `pytest` 9.1.1

---

## 4. Installation & Setup Guide (Windows / PowerShell / VS Code)

### Prerequisites
- Windows 10/11
- Python 3.11 or higher installed and added to PATH
- PowerShell 5.1+ or PowerShell 7+

### Step-by-Step Setup

1. **Open PowerShell and navigate to the project directory**:
   ```powershell
   cd C:\Users\nandh\.gemini\antigravity\scratch\quantum_signature_security
   ```

2. **Create and activate a Python virtual environment (recommended)**:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. **Install dependencies**:
   ```powershell
   python -m pip install -r requirements.txt
   ```

4. **Initialize database & seed demo accounts**:
   ```powershell
   python seed.py
   ```
   *This automatically creates the SQLite database tables and provisions the demo analyst account.*

5. **Run the application**:
   ```powershell
   python run.py
   ```
   *Alternatively, on Windows you can double-click `run.bat` to launch everything in one step.*

6. **Access the application in your browser**:
   Open: **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## 5. Demonstration Analyst Credentials

For local demonstration and academic evaluation:
- **Username**: `demo_analyst`
- **Password**: `CyberSec#2026!`
- **Role**: Tier-1 Quantum Signature Analyst

*(A one-click "Autofill Demo Credentials" button is provided directly on the login screen for rapid evaluation.)*

---

## 6. Application Pages & Features

| # | Page Route | Description |
|---|------------|-------------|
| 1 | `/` | **Landing Page**: Cyber hero banner, security feature pillars, and architecture overview. |
| 2 | `/auth/login` | **Analyst Login**: CSRF-guarded authentication with generic masked error messaging. |
| 3 | `/auth/register` | **Analyst Registration**: Password complexity enforcement and duplicate account prevention. |
| 4 | `/dashboard` | **Security Command Center**: Real DB-backed metrics, 7-day activity trends, threat distribution, and detection category charts. |
| 5 | `/verify` | **Signature Verifier**: Upload or paste message, PEM public key, and Base64 signature. Returns deterministic mathematical verdict and quantum threat assessment. |
| 6 | `/demo-signer` | **Demo Laboratory**: Generates 2048-bit RSA keys, signs sample payloads, and provides buttons to simulate payload bit tampering and signature corruption. |
| 7 | `/analysis` | **Threat Simulator**: Interactive parameter sliders to test burst velocities, key degradation, and observe real-time quantum amplitude rotations and Isolation Forest decisions. |
| 8 | `/events` | **Security Audit Trail**: Granular database event log with date/severity filtering, search, pagination, and CSV download. |
| 9 | `/analysis/<id>` | **Forensic Audit Detail**: Deep-dive record inspection displaying SHA-256 digests, amplitude state decomposition, and SOC recommendations. |
| 10 | `/auth/profile` | **Analyst Profile**: Displays security clearance, last active session, password updates, and personal verification logs. |
| 11 | `/about` | **Theory & Review Guide**: Academic explanation of the Born-rule formula, PQC disclosures, and college evaluation walkthrough. |
| 12 | `404 / 500` | **Custom Error Pages**: Styled cybersecurity error screens with diagnostic codes. |

---

## 7. College Project Review & Demo Walkthrough Script

Follow these steps when demonstrating the project to evaluators:

1. **Step 1: Sign In**: Navigate to `/auth/login`. Click **Autofill Demo Credentials** and log in. Note the session security banner.
2. **Step 2: Generate Demo Keys & Sign**: Go to **Demo Key & Signer** (`/demo-signer`). Notice the 2048-bit RSA key generation. Click **Sign with RSA-PSS SHA-256** to generate the Base64 signature.
3. **Step 3: Verify Valid Signature**: Click **Send Payload to Verifier** and hit **Execute Verification**. Highlight the green **MATHEMATICALLY VALID** badge and the **LOW Risk (< 25.0)** threat score.
4. **Step 4: Demonstrate Tamper Detection**: Return to the Demo Signer. Click **Tamper Message (Mutate Byte)**. Transfer to the Verifier and execute. Demonstrate that modifying even a single character causes immediate **CRYPTOGRAPHIC MISMATCH** with an elevated threat score.
5. **Step 5: Threat Simulator**: Navigate to **Threat Simulator** (`/analysis`). Move the "Rolling Window Failures" slider up to simulate brute-force attacks. Observe how the state vector $|\psi\rangle$ rotates toward $|1\rangle$, elevating the score to **CRITICAL**.
6. **Step 6: Dashboard & Audit Export**: Visit `/dashboard` to show that all charts reflect real database records. Then visit `/events` and click **Export CSV Audit Report** to demonstrate compliance data export.

---

## 8. Automated Testing Suite

The project includes automated tests using `pytest` covering authentication, cryptography, quantum mathematics, routes, and APIs.

### Running the Tests:
```powershell
python -m pytest -v
```

### Test Coverage Highlights:
- **Authentication**: Registration, duplicate prevention, password complexity rules, session masking, logout.
- **Cryptography**: RSA-PSS 2048-bit key generation, valid signature verification, tampered message failure, corrupted Base64 handling, malformed PEM handling.
- **Quantum-Inspired ML**: Feature normalization bounds $[0, 1]$, Born-rule normalization $|\alpha|^2 + |\beta|^2 = 1.0$, monotonic threat score progression, scikit-learn Isolation Forest inference.
- **Routes & Access Control**: Unauthorized redirection, authenticated console access, custom 404 handler.
- **Audit & APIs**: Verification persistence, repeated failure burst detection (`BURST_ATTACK_DETECTED`), dashboard metrics API, CSV export.

---

## 9. Security & Privacy Safeguards

- **Zero Raw Message Storage**: Only the first 100 characters preview and the full SHA-256 digest are recorded in the database. Full sensitive documents are never persisted raw.
- **Zero Private Key Exposure**: Real private keys are never requested by the verification engine. Demonstration private keys generated in the lab are clearly flagged with warning banners.
- **CSRF Defense**: Session-bound cryptographic tokens validate all state-changing POST forms and API calls.
- **Upload Safety**: File uploads are capped at 2MB, restricted to supported extensions, processed in-memory or immediately removed from disk.
- **No User Enumeration**: Login errors use generic messaging ("Invalid username or password") to prevent account discovery.

---

## 10. Security Limitations & Production Disclaimer

> [!IMPORTANT]
> - **Educational & Research Prototype**: This software is designed for academic demonstration, research, and security analysis.
> - **Not a Certificate Authority**: The system verifies cryptographic consistency against the provided public key. Establishing public key identity authenticity requires integration with an enterprise Public Key Infrastructure (PKI) or X.509 Certificate Authority.
> - **Post-Quantum Cryptography**: Classical RSA algorithms are theoretically vulnerable to Shor's algorithm on large-scale fault-tolerant quantum computers. Future production iterations should migrate to NIST-standardized Post-Quantum Cryptography (PQC) digital signature schemes such as ML-DSA (FIPS 204) and SLH-DSA (FIPS 205).
