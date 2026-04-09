"""Multimodal social engineering channels mapping red ops via TinyWorld injections."""

from open_range.channels.email import send_email
from open_range.channels.voice import voice_pretext

__all__ = ["send_email", "voice_pretext"]
