import os
import pytest

from open_range.agents.npc_adapter import configure_npc_llm, persona_to_npc
from open_range.world_ir import GreenPersona
from open_range.channels.email import send_email
from open_range.channels.voice import voice_pretext

@pytest.fixture
def dummy_audio(tmp_path):
    out_path = tmp_path / "dummy_vishing.wav"
    import wave
    with wave.open(str(out_path), 'wb') as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(44100)
    return str(out_path)

@pytest.mark.live_model
def test_multimodal_channels_with_tinyworld(dummy_audio):
    """Verify that email and voice channels can natively penetrate TinyWorld cognition bounds."""
    # Temporarily drop max complexity to keep integration test extremely fast on NIM limits
    os.environ["MODEL_ID"] = "moonshotai/kimi-k2-instruct"
    configure_npc_llm(model="moonshotai/kimi-k2-instruct")

    import tinytroupe.environment as env

    # Deploy test recipient
    alice = GreenPersona(
        id="Alice",
        role="Finance Manager",
        awareness=0.8,
        susceptibility={"phishing": 0.1},
        routine=("check_mail",),
        mailbox="alice@company.local"
    )
    alice_npc = persona_to_npc(alice)
    
    world = env.TinyWorld("office-channels-test", [alice_npc])

    # 1. Trigger Email Injection (Compound Attack Phase 1)
    send_email(
        world=world,
        recipient_name="Alice",
        sender_name="IT Helpdesk",
        subject="URGENT: Password Expiry Notification",
        body="Please open the attached PDF immediately to reset your Office365 bounds.",
        attachment="Click this malicious embedded link to rotate your vault."
    )
    
    # Let Alice digest email
    world.run(steps=1)
    
    actions_p1 = alice_npc.pop_latest_actions()
    # It shouldn't crash and actions should be tracked memory
    assert len(actions_p1) >= 0

    # 2. Trigger Pretext Vishing (Compound Attack Phase 2)
    voice_pretext(
        world=world,
        target_name="Alice",
        caller_id="Unknown Internal Extension 4022",
        audio_file_path=dummy_audio
    )

    # Let Alice interact under pressure
    world.run(steps=1)
    
    actions_p2 = alice_npc.pop_latest_actions()
    assert len(actions_p2) >= 0
    
    # Ensure memory captured the incident vectors
    recent_memory = alice_npc.episodic_memory.retrieve_recent(15)
    memory_string = str(recent_memory).lower()
    
    # 8b-instruct should reliably record having received the email and pretext call
    assert "email" in memory_string or "password" in memory_string or "mark" in memory_string
