"""
Celery application configuration.

This is the entry point Celery's CLI uses when we run:
    celery -A celery_app worker --loglevel=info

The worker container's command (in docker-compose.yml) references this
module by `-A celery_app`, so this file must:
  - Define a Celery instance named `app` (or `celery`)
  - Configure broker / result backend / serializers
  - Trigger task discovery so worker knows which @task functions exist

We use Redis as both broker (job queue) and result backend (where task
return values live). Redis is already in our docker-compose stack and
sized for our scale.
"""
from __future__ import annotations

import os

from celery import Celery


# ----------------------------------------------------------------------------
# Connection URLs
# ----------------------------------------------------------------------------
REDIS_HOST = os.environ["REDIS_HOST"]
REDIS_PORT = int(os.environ["REDIS_PORT"])

# We use Redis DB 0 for both broker and result backend. For our scale this
# is fine — neither queue grows unbounded (we cap result expiry below).
BROKER_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/0"
RESULT_BACKEND_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/0"


# ----------------------------------------------------------------------------
# Celery instance
# ----------------------------------------------------------------------------
app = Celery(
    "reconmesh",
    broker=BROKER_URL,
    backend=RESULT_BACKEND_URL,
    # Tell Celery where to look for @task-decorated functions. Each module
    # listed here gets imported on worker startup; any tasks defined in those
    # modules are then registered with the broker.
    include=[
        "tasks.enrichment_tasks",
        "tasks.mitre_tasks",
    ],
)


# ----------------------------------------------------------------------------
# Defaults applied to every task
# ----------------------------------------------------------------------------
app.conf.update(
    # Use JSON serialization. Default since Celery 4.0, but we set it explicitly
    # so future maintainers know we did NOT pickle. JSON forces task args to
    # be primitives — no SQLAlchemy objects accidentally passed across processes.
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",

    # UTC for any internal timestamps Celery uses
    timezone="UTC",
    enable_utc=True,

    # Silence Celery 6.0 deprecation warning about broker retry on startup
    broker_connection_retry_on_startup=True,

    # Don't keep task results in Redis forever. 1 hour is plenty for the UI
    # to poll once and then forget.
    result_expires=3600,

    # Default timeouts (per task, can be overridden per-task with options).
    # `time_limit` is hard kill; `soft_time_limit` raises SoftTimeLimitExceeded
    # which lets a task clean up.
    task_soft_time_limit=55,
    task_time_limit=60,

    # Retry policy applied to tasks that opt in via autoretry_for / retry_backoff
    task_default_retry_delay=5,    # base delay in seconds
    task_publish_retry=True,

    # Worker behavior
    worker_send_task_events=True,
    task_send_sent_event=True,

    # Acknowledge tasks AFTER they finish, not when picked up. This means
    # if a worker dies mid-task the broker re-delivers the task to another
    # worker. Trade-off: a task could run twice if the worker crashes
    # between task completion and the ack — but our tasks are idempotent
    # (upsert by domain_id + enrichment_type), so this is safe for us.
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)


# ----------------------------------------------------------------------------
# Diagnostic: print registered tasks on startup
# ----------------------------------------------------------------------------
@app.on_after_finalize.connect
def _log_registered_tasks(sender: Celery, **_: dict) -> None:
    """
    Helps catch the classic 'task is not registered' Celery footgun.
    When the worker starts, this prints all the tasks it knows about.
    If our enricher tasks aren't here, the worker can't run them — at
    least we'll see the gap in the logs immediately rather than mystery
    silence.
    """
    user_tasks = sorted(
        name for name in sender.tasks
        if not name.startswith("celery.")
    )
    print("=" * 60)
    print(f"Celery registered {len(user_tasks)} user task(s):")
    for t in user_tasks:
        print(f"  - {t}")
    print("=" * 60)
