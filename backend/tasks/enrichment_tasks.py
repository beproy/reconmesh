"""
Celery tasks for enrichment.

One task per enricher. The /enrich endpoint dispatches all N tasks for a
given domain and returns the EnrichmentJob ID immediately. Each task:

  1. Opens its own DB session (Celery workers don't share FastAPI's request
     scope — each task is its own logical unit of work)
  2. Loads the Domain row by ID (we never pass model objects across the
     wire — JSON serializer wouldn't know how to handle them)
  3. Runs the corresponding enricher (which writes the Enrichment row
     itself, same as in synchronous mode)
  4. Updates the EnrichmentJob counters and lifecycle status
  5. If the enrichment came back with a retryable status (ERROR / TIMEOUT),
     calls self.retry() which triggers Celery's exponential backoff

Retry policy:
  - Up to 3 total attempts per task (so 2 retries after the first failure)
  - Exponential backoff: 5s, 15s, 45s
  - Only retry on ERROR or TIMEOUT — NOT_FOUND is deterministic, never retry
  - Hard time limit of 60s per attempt (set in celery_app.py)

Worst case duration for one task: 60 + 5 + 60 + 15 + 60 = 200s before
giving up. That's fine because the user has a job_id and is polling — not
sitting on a hanging HTTP request.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from celery import Task

from celery_app import app
from database import SessionLocal
from models import (
    Domain,
    EnrichmentJob,
    EnrichmentJobStatus,
    EnrichmentStatus,
    EnrichmentType,
)
from enrichers.base import BaseEnricher
from enrichers.dns_records import DnsEnricher
from enrichers.email_security import EmailSecurityEnricher
from enrichers.whois_lookup import WhoisEnricher
from enrichers.cert_transparency import CertTransparencyEnricher
from enrichers.typo_squat import TypoSquatEnricher
from enrichers.virustotal import VirusTotalEnricher
from enrichers.shodan import ShodanEnricher
from enrichers.abuseipdb import AbuseIPDBEnricher
from enrichers.ahmia import AhmiaEnricher


# Statuses we want to retry on. NOT_FOUND, RATE_LIMITED, OK are all terminal.
RETRYABLE_STATUSES = {EnrichmentStatus.ERROR, EnrichmentStatus.TIMEOUT}

# Retry config: up to 3 total attempts (1 initial + 2 retries).
MAX_RETRIES = 2
RETRY_BACKOFF_BASE = 5  # seconds


# ----------------------------------------------------------------------------
# Generic helpers shared by every task
# ----------------------------------------------------------------------------
def _run_enricher_task(
    task: Task,
    enricher: BaseEnricher,
    job_id: int,
    domain_id: int,
    domain_name: str,
) -> dict:
    """
    Common logic for every enricher task. Each task in this module is a
    thin wrapper that picks the right enricher class then calls this.
    """
    db = SessionLocal()
    try:
        # Mark job as RUNNING on the first task that picks up
        job = db.query(EnrichmentJob).filter(EnrichmentJob.id == job_id).first()
        if job is None:
            # Defensive — shouldn't happen, but if the job row was deleted
            # we just bail. No retry on this case.
            return {
                "status": "skipped",
                "reason": f"EnrichmentJob {job_id} not found",
            }

        if job.status == EnrichmentJobStatus.PENDING:
            job.status = EnrichmentJobStatus.RUNNING
            job.started_at = datetime.now(timezone.utc)
            db.commit()

        # Load the Domain row
        domain = db.query(Domain).filter(Domain.id == domain_id).first()
        if domain is None:
            # Domain deleted between dispatch and task execution. Mark this
            # one as a failed task on the job and bail.
            _increment_job_counter(db, job_id, succeeded=False)
            return {
                "status": "skipped",
                "reason": f"Domain {domain_id} not found",
            }

        # Run the enricher. This persists the Enrichment row itself.
        result = enricher.run_and_save(db, domain)

        # Decide whether to retry. We want retries when the upstream had a
        # transient failure (ERROR / TIMEOUT). NOT_FOUND etc. are terminal.
        if result.status in RETRYABLE_STATUSES and task.request.retries < MAX_RETRIES:
            countdown = RETRY_BACKOFF_BASE * (3 ** task.request.retries)
            print(
                f"[{enricher.enrichment_type.value}] retrying in {countdown}s "
                f"(attempt {task.request.retries + 2}/{MAX_RETRIES + 1}) — "
                f"reason: {result.error_message or result.status.value}"
            )
            # Note: don't increment counters yet — this attempt is being retried
            raise task.retry(countdown=countdown, max_retries=MAX_RETRIES)

        # Terminal outcome (OK, NOT_FOUND, or exhausted retries on ERROR/TIMEOUT).
        # Update the job's counters.
        succeeded = result.status == EnrichmentStatus.OK
        _increment_job_counter(db, job_id, succeeded=succeeded)

        return {
            "status": result.status.value,
            "enrichment_type": enricher.enrichment_type.value,
            "error_message": result.error_message,
        }
    finally:
        db.close()


def _increment_job_counter(db, job_id: int, succeeded: bool) -> None:
    """
    Increment completed_tasks and (if applicable) failed_tasks. When all
    tasks have reported, mark the job COMPLETED. Uses a fresh fetch each
    time to avoid stale counter races between workers.
    """
    job = db.query(EnrichmentJob).filter(EnrichmentJob.id == job_id).first()
    if job is None:
        return

    job.completed_tasks += 1
    if not succeeded:
        job.failed_tasks += 1

    if job.completed_tasks >= job.total_tasks:
        # All tasks reported in. Mark the job as completed (or failed if
        # everything failed).
        if job.failed_tasks >= job.total_tasks:
            job.status = EnrichmentJobStatus.FAILED
        else:
            job.status = EnrichmentJobStatus.COMPLETED
        job.completed_at = datetime.now(timezone.utc)

    db.commit()


# ----------------------------------------------------------------------------
# Tasks — one per enricher
#
# Each task is `bind=True` so it has access to `self.request.retries` and
# `self.retry()`. The task name is explicit so logs/registry are readable.
# ----------------------------------------------------------------------------
@app.task(bind=True, name="enrichment.dns")
def run_dns_task(self: Task, job_id: int, domain_id: int, domain_name: str) -> dict:
    return _run_enricher_task(self, DnsEnricher(), job_id, domain_id, domain_name)


@app.task(bind=True, name="enrichment.email_security")
def run_email_security_task(self: Task, job_id: int, domain_id: int, domain_name: str) -> dict:
    return _run_enricher_task(self, EmailSecurityEnricher(), job_id, domain_id, domain_name)


@app.task(bind=True, name="enrichment.whois")
def run_whois_task(self: Task, job_id: int, domain_id: int, domain_name: str) -> dict:
    return _run_enricher_task(self, WhoisEnricher(), job_id, domain_id, domain_name)


@app.task(bind=True, name="enrichment.ct_logs")
def run_ct_logs_task(self: Task, job_id: int, domain_id: int, domain_name: str) -> dict:
    return _run_enricher_task(self, CertTransparencyEnricher(), job_id, domain_id, domain_name)


@app.task(bind=True, name="enrichment.typo_squat")
def run_typo_squat_task(self: Task, job_id: int, domain_id: int, domain_name: str) -> dict:
    return _run_enricher_task(self, TypoSquatEnricher(), job_id, domain_id, domain_name)


@app.task(bind=True, name="enrichment.virustotal")
def run_virustotal_task(self: Task, job_id: int, domain_id: int, domain_name: str) -> dict:
    return _run_enricher_task(self, VirusTotalEnricher(), job_id, domain_id, domain_name)


@app.task(bind=True, name="enrichment.shodan")
def run_shodan_task(self: Task, job_id: int, domain_id: int, domain_name: str) -> dict:
    return _run_enricher_task(self, ShodanEnricher(), job_id, domain_id, domain_name)


@app.task(bind=True, name="enrichment.abuseipdb")
def run_abuseipdb_task(self: Task, job_id: int, domain_id: int, domain_name: str) -> dict:
    return _run_enricher_task(self, AbuseIPDBEnricher(), job_id, domain_id, domain_name)

@app.task(bind=True, name="enrichment.ahmia")
def run_ahmia_task(self: Task, job_id: int, domain_id: int, domain_name: str) -> dict:
    return _run_enricher_task(self, AhmiaEnricher(), job_id, domain_id, domain_name)

# ----------------------------------------------------------------------------
# Mapping that the API layer uses to dispatch the right tasks
# ----------------------------------------------------------------------------
TASK_FOR_ENRICHMENT_TYPE: dict[EnrichmentType, Task] = {
    EnrichmentType.DNS: run_dns_task,
    EnrichmentType.EMAIL_SECURITY: run_email_security_task,
    EnrichmentType.WHOIS: run_whois_task,
    EnrichmentType.CT_LOGS: run_ct_logs_task,
    EnrichmentType.TYPO_SQUAT: run_typo_squat_task,
    EnrichmentType.VIRUSTOTAL: run_virustotal_task,
    EnrichmentType.SHODAN: run_shodan_task,
    EnrichmentType.ABUSEIPDB: run_abuseipdb_task,
    EnrichmentType.AHMIA: run_ahmia_task,
}
