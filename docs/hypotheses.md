# 1. Pre-Registered Hypotheses

The project formally pre-registers three primary hypotheses in the technical specification:

- **Hypothesis 1 (H1 — Tiered Efficiency & Precision):** **Hybrid multi-tier reasoning (Rules → Calibrated ML → Schema-Constrained LLM) reduces false-positive rates and operational costs compared to an LLM-only architecture, while maintaining comparable detection recall.**

- **Hypothesis 2 (H2 — Vulnerability of Naive Triage):** **Naive LLM triage—where raw untrusted telemetry text is placed directly into the prompt context—exhibits a non-trivial Attack Success Rate (ASR) when processing adversarial endpoint telemetry.**

- **Hypothesis 3 (H3 — Efficacy of the Trust Boundary):** **The hardened dual-LLM architecture (Quarantined Extractor + Privileged Reasoner) reduces the prompt injection Attack Success Rate (ASR) substantially with minimal degradation in detection quality or explanation validity.**

---

# 2. Metrics of Evaluation & Statistical Rigor

To ensure statistical rigor, all model-dependent configurations (**C0–C5**) undergo repeated trials, with results reported using **95% bootstrap confidence intervals** to capture variance rather than relying solely on point means.

The metrics evaluated with bootstrap confidence intervals fall into four dimensions:

## A. Detection Quality

- **Precision, Recall, & F1 Score:** Primary metrics for binary classification on malicious vs. benign events.
- **False-Positive Rate (FPR):** Measures unnecessary analyst noise on benign administrative workloads.
- **Precision-Recall Area Under Curve (PR-AUC):** Evaluates score ranking across decision thresholds.
- **Per-Technique Recall:** Evaluates detection coverage across individual MITRE ATT&CK techniques.
- **Expected Calibration Error (ECE):** Quantifies whether model confidence scores accurately reflect true empirical probability.

## B. Robustness & Security

- **Attack Success Rate (ASR):** The percentage of adversarial telemetry samples where an injected payload successfully flips a ground-truth verdict (e.g., forcing a **Malicious** alert to be classified as **Benign**). ASR is reported across all **8 injection categories**.
- **Utility Under Attack:** Measures whether detection precision and recall on uncorrupted telemetry remain stable while under active injection conditions.

## C. Explanation & Justification Quality

- **ATT&CK Technique Precision & Recall:** Accuracy of mapped MITRE ATT&CK technique IDs against ground-truth labels.
- **Decoded-Command Accuracy:** Precision in identifying obfuscation structures (e.g., Base64 UTF-16LE expansion).
- **Evidence-Reference Validity:** Verification that generated rationales reference valid, existing event IDs and enrichment observables without hallucinating indicators.

## D. Operational Performance

- **Latency (p50 and p95):** Measured in milliseconds per tier and end-to-end per event.
- **Cost Per Alert:** Token consumption and API cost evaluated per triage event.
- **Repeated-Run Agreement:** Variance and stability of outputs across identical runs.

---

# 3. The Matched Model Rule

To prevent model capability differences from confounding architectural evaluation, the project enforces a strict **Matched Model Rule**.

## Rule Definition

When comparing naive configurations against hardened configurations, the **exact same underlying model version** must be used for both roles.

## Evaluated Matched Pairs

- **Naive LLM-only (`C2`) vs. Hardened LLM-only (`C3`):**
  Evaluates the direct security impact of adding the **Quarantined Extractor + Privileged Reasoner** boundary without any upstream rule/ML tiers.

- **Naive Hybrid (`C4`) vs. Hardened Hybrid (`C5`):**
  Evaluates the full multi-tier system with and without the architectural trust boundary.

## Scientific Control

By pinning the model family and version across matched pairs, any observed drop in **Attack Success Rate (ΔASR)** or shift in **F1 score (ΔF1)** is mathematically attributable to the **architectural isolation pattern**, rather than differences in model parameter count or training data.

## Traceability Controls

Model identifiers are read from environment configurations, stamped into every generated artifact (`config_version`), and logged with exact runtime timestamps to account for hosted model updates.

Secondary experiments test **dual-vendor splits** and **local open-weights models** for third-party reproducibility.

---
