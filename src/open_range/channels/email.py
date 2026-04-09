"""Email multimodal social engineering channel."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tinytroupe.agent import TinyPerson
    from tinytroupe.environment import TinyWorld

logger = logging.getLogger(__name__)


def send_email(
    world: "TinyWorld",
    recipient_name: str,
    sender_name: str,
    subject: str,
    body: str,
    attachment: str | None = None,
) -> None:
    """Inject an email directly into a target NPC's context stream using the SDK.
    
    Translates the Red/Blue event payload natively into TinyTroupe's listen() 
    and store_in_memory() multimodal capabilities.
    """
    target: TinyPerson | None = world.get_agent_by_name(recipient_name)
    if not target:
        logger.warning("Email recipient '%s' not found in TinyWorld", recipient_name)
        return

    # Frame the email perfectly as an organizational interaction
    email_injection = (
        f"You just received an email from '{sender_name}' with the subject: '{subject}'.\n\n"
        f"Body:\n{body}\n\n"
    )

    if attachment:
        email_injection += f"There is a document attached to this email. You decide to open and read it. Attachment contents:\n{attachment}\n"

    # Instead of broadcasting to everyone, target specifically listnes
    logger.info("Delivering email %s -> %s", sender_name, recipient_name)
    target.listen(email_injection)
