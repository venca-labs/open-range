"""Voice pretext multimodal social engineering channel."""

from __future__ import annotations

import logging
import os
import requests
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tinytroupe.agent import TinyPerson
    from tinytroupe.environment import TinyWorld

logger = logging.getLogger(__name__)


def voice_pretext(world: "TinyWorld", target_name: str, caller_id: str, audio_file_path: str) -> None:
    """Execute an end-to-end voice channel vishing attack in OpenRange.
    
    1. Transcribes incoming attacking audio via NVIDIA Parakeet ASR.
    2. Feeds transcript to the target NPC running Kimi/Llama backend.
    3. Triggers the NPC's voice response.
    4. Synthesizes the NPC's reply via NVIDIA FastPitch Riva TTS.
    """
    target: TinyPerson | None = world.get_agent_by_name(target_name)
    if not target:
        logger.warning("Voice target '%s' not found", target_name)
        return

    # 1. Automatic Speech Recognition (ASR) via Parakeet
    asr_endpoint = os.environ.get("ASR_URL", "http://parakeet-asr.openrange-internal.svc:9000/v1/audio/transcriptions")
    
    logger.info("Transcribing audio payload %s via %s", audio_file_path, asr_endpoint)
    
    transcript = "<Unintelligible audio>"
    if os.path.exists(audio_file_path):
        try:
            with open(audio_file_path, 'rb') as f:
                res = requests.post(
                    asr_endpoint,
                    files={"file": f},
                    data={"model": "nvidia/parakeet-ctc-riva-8m"},
                    headers={"Authorization": f"Bearer {os.environ.get('NVIDIA_API_KEY', '')}"}
                )
            res.raise_for_status()
            transcript = res.json().get("text", "")
        except requests.exceptions.RequestException as e:
            logger.error("ASR Parakeet translation failed: %s. Falling back to dummy text.", e)
            transcript = "Hello, this is IT. We need your password." # Fallback for test bounds
    else:
        logger.error("Audio payload missing!")

    # 2. Inject context directly into generic multimodal LLM Pipeline
    injection = (
        f"Your desk phone rings. The caller ID shows '{caller_id}'.\n"
        f"You answer, and hear the following transcript:\n\n\"{transcript}\"\n\n"
        "How do you defensively respond to this request on the spot under pressure?"
    )

    logger.info("Ringing desk phone of %s (caller: %s)", target_name, caller_id)
    target.listen(injection)

    # 3. Predict the action or pull the next verbal reply
    # OpenRange NPCs will actively act() using Kimi or Llama. 
    target.act()

    # 4. Synthesize Response (TTS) via Riva
    latest_actions = target.pop_latest_actions()
    verbal_replies = [a.get("content") for a in latest_actions if a.get("action", {}).get("type") == "TALK"]

    tts_endpoint = os.environ.get("TTS_URL", "http://fastpitch-tts.openrange-internal.svc:9000/v1/audio/speech")
    
    if verbal_replies:
        npc_reply = verbal_replies[-1]
        logger.info("NPC '%s' verbal reply synthesized: %s", target_name, npc_reply)
        
        try:
            res_tts = requests.post(
                tts_endpoint,
                json={
                    "model": "nvidia/fastpitch",
                    "input": npc_reply,
                    "voice": "alloy"
                },
                headers={
                    "Authorization": f"Bearer {os.environ.get('NVIDIA_API_KEY', '')}",
                    "Content-Type": "application/json"
                }
            )
            
            if res_tts.status_code == 200:
                out_path = f"/tmp/vishing_reply_{target_name}.wav"
                with open(out_path, 'wb') as f:
                    f.write(res_tts.content)
                logger.info("Saved NVIDIA TTS synthetic reply to %s", out_path)
        except requests.exceptions.RequestException as e:
            logger.error("TTS FastPitch serialization failed: %s", e)
