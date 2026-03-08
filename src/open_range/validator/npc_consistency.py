"""Check 9: NPC consistency — verify personas respond per security_awareness.

If no NPC personas are configured the check passes vacuously.  When personas
exist we first validate persona card sanity (mechanical), then send calibrated
test phishing stimuli to each persona via LLM to verify behavioral consistency.

High-awareness (>=0.8) NPCs MUST reject a test phishing stimulus.
Low-awareness (<=0.3) NPCs SHOULD fall for a well-crafted lure.

This check is advisory: failure triggers retry but never hard-rejects.
"""

from __future__ import annotations

import json
import logging
import os

from open_range.protocols import CheckResult, ContainerSet, NPCPersona, SnapshotSpec

logger = logging.getLogger(__name__)

# Test phishing stimulus crafted for each persona's role.
_PHISHING_TEMPLATE = """\
From: IT Support <it-helpdesk@{company_domain}>
Subject: Urgent: Password Reset Required

Hi {name},

Due to a recent security audit, all employees in {department} are required \
to reset their passwords immediately. Please click the link below and enter \
your current credentials to verify your identity:

https://corporate-portal-auth.{company_domain}/reset?user={username}

This must be completed within 24 hours or your account will be locked.

Best regards,
IT Support Team
"""

NPC_CONSISTENCY_PROMPT = """\
You are simulating the following employee in a corporate environment for a \
validation test. You will receive a persona card and a test email. Based on \
the persona's security_awareness and susceptibility profile, decide how this \
person would respond.

You MUST stay in character. Consider:
- security_awareness level (0.0 = completely unaware, 1.0 = expert)
- susceptibility.phishing_email score
- The persona's communication style and role
- Whether the email has red flags (urgency, suspicious links, credential requests)

Return ONLY valid JSON:
{
  "action": "<click_link|reply_with_credentials|ignore|report_to_IT|forward>",
  "reasoning": "<brief in-character explanation of why the persona chose this action>",
  "suspicious_elements_noticed": ["<list of red flags the persona noticed, if any>"]
}
"""

# Actions that indicate the NPC "fell for" the phishing attempt.
# All lowercase — we normalize LLM output with .lower() before matching.
_FELL_FOR_ACTIONS = {"click_link", "reply_with_credentials", "open_attachment", "share_credentials"}
# Actions that indicate the NPC "rejected" the phishing attempt.
_REJECTED_ACTIONS = {"ignore", "report_to_it", "forward"}


class NPCConsistencyCheck:
    """Validate NPC persona cards and behavioral consistency via LLM.

    Always advisory — failure triggers retry but never blocks admission.
    """

    def __init__(self, model: str | None = None) -> None:
        self.model = model or os.environ.get(
            "OPENRANGE_NPC_MODEL", "anthropic/claude-haiku-4-5-20251001"
        )

    async def check(self, snapshot: SnapshotSpec, containers: ContainerSet) -> CheckResult:
        personas = snapshot.npc_personas
        if not personas:
            return CheckResult(
                name="npc_consistency",
                passed=True,
                advisory=True,
                details={"note": "no NPC personas configured — vacuously true"},
            )

        issues: list[str] = []

        # --- Phase 1: Mechanical persona card validation ----------------------
        for p in personas:
            issues.extend(_validate_persona_card(p))

        # If mechanical checks already fail, skip the LLM phase.
        if issues:
            return CheckResult(
                name="npc_consistency",
                passed=False,
                advisory=True,
                details={"personas_checked": len(personas), "issues": issues},
                error=f"{len(issues)} NPC consistency issue(s)",
            )

        # --- Phase 2: LLM behavioral testing ---------------------------------
        behavioral_issues = await self._test_npc_behaviors(personas)
        issues.extend(behavioral_issues)

        passed = len(issues) == 0
        return CheckResult(
            name="npc_consistency",
            passed=passed,
            advisory=True,
            details={"personas_checked": len(personas), "issues": issues},
            error="" if passed else f"{len(issues)} NPC consistency issue(s)",
        )

    async def _test_npc_behaviors(self, personas: list[NPCPersona]) -> list[str]:
        """Send test phishing stimuli to personas via LLM and check responses."""
        try:
            import litellm  # noqa: F811
        except ImportError:
            logger.info("litellm not installed — skipping NPC behavioral test")
            return []

        issues: list[str] = []
        company_domain = "acmecorp.local"

        for p in personas:
            # Only test personas with clear high or low awareness.
            if p.security_awareness < 0.3 or p.security_awareness >= 0.8:
                stimulus = _PHISHING_TEMPLATE.format(
                    company_domain=company_domain,
                    name=p.name,
                    department=p.department or "General",
                    username=p.accounts.get("ldap", p.name.lower().replace(" ", ".")),
                )

                try:
                    response = await litellm.acompletion(
                        model=self.model,
                        messages=[
                            {"role": "system", "content": NPC_CONSISTENCY_PROMPT},
                            {
                                "role": "user",
                                "content": json.dumps({
                                    "persona": p.model_dump(),
                                    "stimulus": {
                                        "type": "email",
                                        "content": stimulus,
                                        "sender": f"it-helpdesk@{company_domain}",
                                        "subject": "Urgent: Password Reset Required",
                                    },
                                }),
                            },
                        ],
                        response_format={"type": "json_object"},
                        temperature=0.0,
                    )

                    raw = json.loads(response.choices[0].message.content)
                    action = raw.get("action", "ignore").lower().strip()

                    # High-awareness NPCs MUST reject phishing.
                    if p.security_awareness >= 0.8 and action in _FELL_FOR_ACTIONS:
                        issues.append(
                            f"{p.name}: security_awareness={p.security_awareness} "
                            f"but fell for test phishing (action={action})"
                        )

                    # Low-awareness NPCs SHOULD fall for well-crafted phishing.
                    if p.security_awareness < 0.3 and action in _REJECTED_ACTIONS:
                        issues.append(
                            f"{p.name}: security_awareness={p.security_awareness} "
                            f"but rejected test phishing (action={action}); "
                            f"persona may be miscalibrated"
                        )

                except Exception as exc:  # noqa: BLE001
                    # LLM failure should not block — degrade gracefully.
                    logger.warning(
                        "NPC consistency LLM test for %s failed: %s", p.name, exc
                    )
                    # Don't add an issue — LLM failure is not a persona problem.

        return issues


def _validate_persona_card(p: NPCPersona) -> list[str]:
    """Mechanical validation of a persona card's internal consistency."""
    issues: list[str] = []

    # security_awareness must be in [0, 1].
    if not (0.0 <= p.security_awareness <= 1.0):
        issues.append(
            f"{p.name}: security_awareness {p.security_awareness} out of [0, 1]"
        )

    # High-awareness NPCs should have low susceptibility scores.
    if p.security_awareness >= 0.8:
        for attack_type, score in p.susceptibility.items():
            if score > 0.5:
                issues.append(
                    f"{p.name}: high awareness ({p.security_awareness}) but "
                    f"susceptibility.{attack_type}={score} (expected <=0.5)"
                )

    # Low-awareness NPCs should have at least one high susceptibility.
    if p.security_awareness <= 0.3:
        if p.susceptibility and all(v < 0.3 for v in p.susceptibility.values()):
            issues.append(
                f"{p.name}: low awareness ({p.security_awareness}) but "
                f"all susceptibility scores < 0.3"
            )

    return issues
