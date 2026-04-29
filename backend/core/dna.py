"""
Production-grade Digital DNA signature generation and matching for CyberShield.
"""
import hashlib
import time
from difflib import SequenceMatcher


def generate_dna_signature(event_data):
    """
    Generate a structured DNA signature from event data.
    """
    sig = {
        "id": hashlib.sha256(str(event_data).encode()).hexdigest(),
        "actions": event_data.get("actions", []),
        "extensions": event_data.get("extensions", []),
        "speed": event_data.get("speed", "unknown"),
        "sequence": event_data.get("sequence", []),
        "impact_score": event_data.get("impact_score", 0),
        "timestamp": time.time(),
        "source_node": event_data.get("source_node", "local")
    }
    return sig


def dna_similarity(sig1, sig2):
    """
    Compute similarity score (0-100) between two DNA signatures.
    """
    score = 0
    # Actions
    actions1 = set(sig1.get("actions", []))
    actions2 = set(sig2.get("actions", []))
    if actions1 or actions2:
        score += 30 * len(actions1 & actions2) / max(len(actions1 | actions2), 1)
    # Extensions
    ext1 = set(sig1.get("extensions", []))
    ext2 = set(sig2.get("extensions", []))
    if ext1 or ext2:
        score += 20 * len(ext1 & ext2) / max(len(ext1 | ext2), 1)
    # Sequence (order matters)
    seq1 = sig1.get("sequence", [])
    seq2 = sig2.get("sequence", [])
    if seq1 and seq2:
        seq_score = SequenceMatcher(None, seq1, seq2).ratio()
        score += 30 * seq_score
    # Speed
    if sig1.get("speed") == sig2.get("speed"):
        score += 10
    # Impact score (within 10)
    if abs(sig1.get("impact_score", 0) - sig2.get("impact_score", 0)) <= 10:
        score += 10
    return round(score)
