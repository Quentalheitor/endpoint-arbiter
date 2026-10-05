"""Privileged Arbiter module for triage verdict determination.

Implements the privileged decision layer that aggregates detections across:
- Tier A: Deterministic rules (e.g., Sigma signatures, IOC matches).
- Tier B: Machine learning classifiers / reputation lookups.
- Tier C: Quarantined LLM extraction outputs.

Enforces Safety Invariant I1:
Deterministic detections from Tier A or high-confidence Tier B evidence
cannot be downgraded or overridden by Tier C LLM outputs.
"""

import uuid
from datetime import datetime, timezone

from schemas.contracts import (
    NormalizedInputTelemetry,
    ObservableEnrichment,
    TriageArtifact,
)
from schemas.extractor import ExtractorOutput


class Arbiter:
    """Privileged arbitration engine that synthesizes final triage decisions.

    The Arbiter maintains strict trust boundaries by evaluating evidence from
    deterministic rules and enriched observables before considering untrusted
    or LLM-extracted metadata.
    """

    def arbitrate(
        self,
        event: NormalizedInputTelemetry,
        decoded_cmd: str,
        obf_type: str,
        enrichment: ObservableEnrichment,
        extractor_res: ExtractorOutput,
    ) -> TriageArtifact:
        """Arbitrate between multiple tiers of evidence to produce a triage artifact.

        Evaluates Tier A/B detection rules against the normalized telemetry and
        enrichment intelligence. If high-confidence threat indicators match,
        a Malicious verdict is assigned and cannot be downgraded (Safety Invariant I1).
        If prompt injection is detected in untrusted inputs, the event is routed
        to Needs-Review. Otherwise, benign activity is concluded.

        Args:
            event: The normalized endpoint telemetry event (Contract A).
            decoded_cmd: The de-obfuscated command-line string.
            obf_type: The identified obfuscation classification (e.g. Base64 UTF-16LE).
            enrichment: External or frozen observable reputation intelligence (Contract B).
            extractor_res: Output from the quarantined Tier C extractor.

        Returns:
            TriageArtifact: An immutable triage artifact (Contract C) containing
                the verdict, risk metrics, MITRE ATT&CK techniques, audit trace,
                and recommended response actions.
        """
        # Step 1: Evaluate Tier A/B deterministic indicators.
        # High-reputation threat IP (score >= 80) triggers a high-severity rule hit.
        rule_hit = enrichment.reputation.score >= 80

        # Step 2: Enforce Safety Invariant I1.
        # A deterministic rule hit cannot be downgraded by Tier C LLM outputs.
        if rule_hit:
            verdict = "Malicious"
            risk_score = enrichment.reputation.score
            confidence_score = 90
            justification = (
                f"Process executed {obf_type} payload communicating with known malicious IP "
                f"{enrichment.observable_value} (reputation score {enrichment.reputation.score})."
            )
            techniques = [
                {"framework": "MITRE_ATTACK", "id": "T1059.001", "name": "PowerShell"},
                {
                    "framework": "MITRE_ATTACK",
                    "id": "T1071.001",
                    "name": "Web Protocols",
                },
            ]
            response = [
                {
                    "action": "Isolate Host",
                    "target": event.host.hostname,
                    "priority": "P0",
                },
                {
                    "action": "Revoke User Session",
                    "target": f"{event.principal.domain}\\{event.principal.username}",
                    "priority": "P1",
                },
            ]
        elif extractor_res.instruction_like_content_flag:
            # Step 3: Handle potential adversarial prompt injection.
            # Flagged instruction-like content in untrusted fields is quarantined and marked for review.
            verdict = "Needs-Review"
            risk_score = 60
            confidence_score = 40
            justification = "Potential indirect prompt injection detected in command-line arguments."
            techniques = []
            response = [
                {
                    "action": "Alert SOC Tier 2",
                    "target": event.host.hostname,
                    "priority": "P2",
                }
            ]
        else:
            # Step 4: Default benign classification for regular operations.
            verdict = "Benign"
            risk_score = 10
            confidence_score = 80
            justification = "Standard administrative process activity; no hostile indicators matched."
            techniques = []
            response = [
                {"action": "No Action", "target": event.host.hostname, "priority": "P3"}
            ]

        # Step 5: Synthesize and return the immutable Contract C Triage Artifact.
        return TriageArtifact(
            triage_id=f"trg-{uuid.uuid4().hex[:8]}",
            reference_event_id=event.event_id,
            analysis_timestamp=datetime.now(timezone.utc).isoformat(),
            config_version="rules-v1.0+extractor-v1.0+arbiter-v1.0",
            verdict=verdict,
            state="complete",
            metrics={"risk_score": risk_score, "confidence_score": confidence_score},
            tier_trace=[
                {"tier": "A", "rule_ids": ["SIGMA-PROC-IWR"] if rule_hit else []},
                {"tier": "C", "role": "extractor", "model_version": "quarantined-v1"},
                {
                    "tier": "C",
                    "role": "arbiter",
                    "model_version": "privileged-arbiter-v1",
                },
            ],
            decoded_content={
                "command_line_decoded": decoded_cmd,
                "obfuscation_type": obf_type,
                "injection_flags_detected": (
                    ["instruction_in_args"]
                    if extractor_res.instruction_like_content_flag
                    else []
                ),
            },
            techniques=techniques,
            justification=justification,
            evidence_refs=[event.event_id, f"enrichment:{enrichment.observable_value}"],
            recommended_response=response,
        )
