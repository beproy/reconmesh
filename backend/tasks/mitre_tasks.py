"""
Celery tasks for MITRE ATT&CK data refresh.

Single task: refresh_mitre_attack. Manual trigger only (no Beat schedule).

Time limits are overridden vs. the global 60s default in celery_app.py —
the MITRE bundle is large enough that ingest can take a few minutes.

No retries: this is an operator-triggered task. If it fails, the operator
re-triggers. Auto-retries would mask network issues that we want visible.
"""
from __future__ import annotations

from celery import Task

from celery_app import app
from database import SessionLocal
from ingesters.mitre_attack import MitreAttackIngester


# 10 minutes hard, 9 soft — plenty of margin for a 35MB bundle + ~20k objects.
TASK_TIME_LIMIT = 600
TASK_SOFT_TIME_LIMIT = 540


@app.task(
    bind=True,
    name="ingest.mitre_attack",
    time_limit=TASK_TIME_LIMIT,
    soft_time_limit=TASK_SOFT_TIME_LIMIT,
)
def refresh_mitre_attack(self: Task) -> dict:
    """
    Fetch the MITRE ATT&CK Enterprise STIX bundle and upsert into our
    4 attack_* tables. Returns a stats dict that the API exposes via
    GET /tasks/{task_id}.
    """
    db = SessionLocal()
    try:
        ingester = MitreAttackIngester()
        stats = ingester.ingest(db)
        return {
            "feed": "MITRE ATT&CK",
            "fetched_bytes": stats.fetched,
            "parsed": stats.parsed,
            "inserted": stats.inserted,
            "updated": stats.updated,
            "skipped": stats.skipped,
            "errors": stats.errors,
            "groups": stats.groups,
            "techniques": stats.techniques,
            "malware": stats.malware,
            "relationships": stats.relationships,
        }
    finally:
        db.close()
