from app.storage import database as db


def test_incident_stats_returns_expected_keys():
    stats = db.get_incident_stats()

    assert isinstance(stats, dict)
    assert "total" in stats
    assert "attacks" in stats
    assert "benign" in stats
    assert "llm_decided" in stats
