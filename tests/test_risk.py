from exif_killer.risk import classify_metadata


def test_risk_classification_uses_shared_categories() -> None:
    findings = classify_metadata(
        "image",
        {
            "Artist": "Unit Tester",
            "FileCreated": "2026-04-22 12:00:00",
            "Format": "JPEG",
            "JavaScript": "PRESENT",
            "Zone.Identifier": "PRESENT",
        },
    )

    by_key = {finding.key: finding.category for finding in findings}

    assert by_key["Artist"] == "identifying"
    assert by_key["FileCreated"] == "filesystem"
    assert by_key["Format"] == "technical"
    assert by_key["JavaScript"] == "embedded-content"
    assert by_key["Zone.Identifier"] == "tracking"
