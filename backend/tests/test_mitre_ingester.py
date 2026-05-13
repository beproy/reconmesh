"""
Smoke tests for the MITRE ATT&CK ingester.

Following the project's existing test style: real DB, no mocks, terse
assertions on the most-likely-to-break paths.

We deliberately do NOT hit the real GitHub bundle URL here — that's a
30+ MB download we don't want on every pytest run. The parser is
exercised against a minimal inline STIX bundle with one of each object
type plus one revoked object to confirm the skip logic.

Run inside the backend container:
    docker compose exec backend pytest tests/test_mitre_ingester.py -v
"""
from __future__ import annotations

from ingesters.mitre_attack import MitreAttackIngester


# ----------------------------------------------------------------------------
# Tiny inline STIX bundle — 4 valid objects, 1 revoked, 1 unsupported type
# ----------------------------------------------------------------------------
MINIMAL_BUNDLE = {
    "type": "bundle",
    "id": "bundle--test-0001",
    "objects": [
        {
            "type": "intrusion-set",
            "id": "intrusion-set--test-group-0001",
            "name": "Test Group",
            "description": "A test group.",
            "aliases": ["Test Group", "TG-001"],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "G9999"}
            ],
            "created": "2024-01-01T00:00:00.000Z",
            "modified": "2024-01-01T00:00:00.000Z",
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--test-technique-0001",
            "name": "Test Technique",
            "description": "A test technique.",
            "x_mitre_is_subtechnique": False,
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
            ],
            "x_mitre_platforms": ["Linux", "Windows"],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T9999"}
            ],
            "created": "2024-01-01T00:00:00.000Z",
            "modified": "2024-01-01T00:00:00.000Z",
        },
        {
            "type": "malware",
            "id": "malware--test-malware-0001",
            "name": "TestMalware",
            "description": "A test malware family.",
            "is_family": True,
            "x_mitre_aliases": ["TestMalware", "TM"],
            "malware_types": ["trojan"],
            "x_mitre_platforms": ["Windows"],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "S9999"}
            ],
            "created": "2024-01-01T00:00:00.000Z",
            "modified": "2024-01-01T00:00:00.000Z",
        },
        {
            "type": "relationship",
            "id": "relationship--test-rel-0001",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--test-group-0001",
            "target_ref": "malware--test-malware-0001",
            "description": "Test Group uses TestMalware.",
            "created": "2024-01-01T00:00:00.000Z",
            "modified": "2024-01-01T00:00:00.000Z",
        },
        {
            # Revoked — must be skipped
            "type": "intrusion-set",
            "id": "intrusion-set--revoked-0001",
            "name": "Revoked Group",
            "revoked": True,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "G9998"}
            ],
        },
        {
            # Unsupported type — must be skipped (silently)
            "type": "tool",
            "id": "tool--test-tool-0001",
            "name": "Test Tool",
        },
    ],
}


# ----------------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------------
def test_mitre_ingester_instantiates():
    """
    Basic sanity: the ingester class loads and has the expected attributes.
    Mirrors the URLhaus smoke test pattern.
    """
    ingester = MitreAttackIngester()
    assert ingester.name == "MITRE ATT&CK"
    assert ingester.source_url.startswith("https://")
    assert ingester.source_type is not None


def test_mitre_parse_bundle_skips_revoked_and_unsupported():
    """
    parse_bundle() should yield only the 4 valid objects from MINIMAL_BUNDLE,
    skipping the revoked intrusion-set. Unsupported types (tool) are
    yielded by parse_bundle but dropped later by the dispatcher — we test
    that they don't cause exceptions.
    """
    ingester = MitreAttackIngester()
    yielded = list(ingester.parse_bundle(MINIMAL_BUNDLE))

    # 6 objects in the bundle, 1 is revoked → 5 yielded
    assert len(yielded) == 5

    # None of the yielded objects should be the revoked one
    yielded_ids = {obj["id"] for obj in yielded}
    assert "intrusion-set--revoked-0001" not in yielded_ids


def test_mitre_extract_attack_id():
    """
    The attack_id (G9999, T9999, S9999) must be pulled from the
    mitre-attack entry in external_references.
    """
    ingester = MitreAttackIngester()
    group = MINIMAL_BUNDLE["objects"][0]
    assert ingester._extract_attack_id(group) == "G9999"

    # An object with no mitre-attack ref returns None
    no_ref = {"external_references": [{"source_name": "other", "external_id": "X"}]}
    assert ingester._extract_attack_id(no_ref) is None
