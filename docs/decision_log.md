# Detection & Ingestion Architecture

## How Sigma Rules Work (Tier A)

Tier A (Detection Rules) operates as the deterministic, first-line reasoning tier engineered for high-speed, explainable threat identification.

* **Open Standard & MITRE ATT&CK Mapping:** Built on open community Sigma rules mapped directly to MITRE ATT&CK technique IDs (e.g., `T1059.001` for PowerShell).
* **Execution Pipeline Placement:** Evaluated during **Stage 4 (Tiered Reasoning)**, strictly downstream of:
  * **Stage 1:** OCSF Normalization
  * **Stage 2:** Deterministic Decoding (de-obfuscating Base64/UTF-16LE payloads and shell variable-expansion tricks prior to matching)
* **Matching Engine:** Rules run via an in-process matcher or compile into columnar DuckDB SQL queries executed directly against structured event fields.
* **Authoritative Hits & Safety Invariant (I1):** Tier A matches are authoritative. Under **Safety Invariant I1**, downstream LLM tiers may escalate an alert's severity, but they are strictly barred from downgrading a deterministic, high-confidence Tier A detection.
* **Artifact Traceability:** Matching rules stamp their identifiers (`rule_ids`) and corresponding ATT&CK technique IDs into the immutable triage artifact's `tier_trace` and `techniques` fields.

---

## Why OCSF v1.3 (Class 1007: Process Activity) Was Chosen

Adopting OCSF v1.3 Class 1007 standardizes the ingestion layer across three key operational areas:

### 1. Telemetry Heterogeneity Resolution
* Reconciles disparate, proprietary log formats from multiple EDR vendors and operating systems.
* Imposes a vendor-neutral data contract with enforced UTC ISO-8601 timestamp coercion.

### 2. Native Process Lineage Modeling
* Maps the full process execution context in a unified structure:
  * **Process Metadata:** `process.pid`, `process.name`, `process.command_line`, and executable hashes.
  * **Contextual Entities:** Host details (`device`) and actor identity (`actor.user`).
  * **Execution Chains:** Preserves parent-child lineage (e.g., `cmd.exe` → `powershell.exe`).

### 3. Canonical Integrity & Taint Tracking
* Enables Stage 1 to generate a cryptographic **SHA-256 canonical event hash** for tamper-evident non-repudiation.
* Systematically identifies and flags attacker-controllable input via `untrusted_fields` (e.g., raw `process.command_line`) before downstream processing.
