import pytest
from backend.core.dna import generate_dna_signature, dna_similarity
from pathlib import Path

def test_generate_dna_signature(tmp_path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("test")
    sig = generate_dna_signature(file_path)
    assert isinstance(sig, dict)
    assert "id" in sig

def test_dna_similarity():
    sig1 = {"id": "abc", "sequence": [1,2,3]}
    sig2 = {"id": "def", "sequence": [1,2,3]}
    score = dna_similarity(sig1, sig2)
    assert 0 <= score <= 100
