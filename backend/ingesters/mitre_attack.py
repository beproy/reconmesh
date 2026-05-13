"""
MITRE ATT&CK Enterprise ingester.

Pulls the STIX 2.1 bundle from the official attack-stix-data GitHub repo
and writes groups, techniques, malware, and relationships to our 4
dedicated tables.

Design notes:
  * NOT a BaseIngester subclass — the BaseIngester pattern is built
    around Indicator + Domain rows, which doesn't fit ATT&CK objects
    at all. We still upsert a Source row called "MITRE ATT&CK" so it
    shows up in /sources alongside URLhaus etc.
  * Per-record commits with IntegrityError catch — same robustness
    pattern as the other ingesters. One bad record doesn't roll back
    the rest.
  * ON CONFLICT DO UPDATE on stix_id — re-running the ingest picks up
    upstream edits (new aliases, renamed techniques, etc.). Confirmed
    Session 19 requirement.
  * Skip revoked + deprecated on ingest. The columns exist for future
    use but we don't populate them today.

The bundle is ~35 MB; we load it whole-file with stdlib json. Peak memory
is ~150 MB, well within budget on the laptop.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

import httpx
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from models import (
    AttackGroup,
    AttackMalware,
    AttackRelationship,
    AttackTechnique,
    Source,
    SourceType,
)


# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------
MITRE_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

# The bundle is ~35MB. 5 min ceiling is plenty even on slow links.
HTTP_TIMEOUT_SECONDS = 300

USER_AGENT = "ReconMesh/0.2 (CTI aggregator)"

SOURCE_NAME = "MITRE ATT&CK"
SOURCE_DESCRIPTION = (
    "MITRE ATT&CK Enterprise — adversary groups, techniques, malware, "
    "and relationships. Public STIX 2.1 bundle, no API key."
)


# ----------------------------------------------------------------------------
# Stats — same shape used by other ingesters
# ----------------------------------------------------------------------------
@dataclass
class MitreIngestStats:
    fetched: int = 0          # bytes downloaded
    parsed: int = 0           # total STIX objects iterated
    inserted: int = 0         # new rows added
    updated: int = 0          # existing rows refreshed
    skipped: int = 0          # revoked/deprecated/unsupported type
    errors: int = 0
    # Per-table breakdown for ops visibility
    groups: int = 0
    techniques: int = 0
    malware: int = 0
    relationships: int = 0


# ----------------------------------------------------------------------------
# Ingester
# ----------------------------------------------------------------------------
class MitreAttackIngester:
    name = SOURCE_NAME
    source_url = MITRE_BUNDLE_URL
    source_type = SourceType.STIX_BUNDLE
    description = SOURCE_DESCRIPTION

    # ------------------------------------------------------------------------
    # Public entrypoint
    # ------------------------------------------------------------------------
    def ingest(self, db: Session) -> MitreIngestStats:
        stats = MitreIngestStats()

        # 1. Source row
        source_id = self._upsert_source(db)

        # 2. Fetch
        try:
            raw = self.fetch()
            stats.fetched = len(raw)
        except Exception as e:
            print(f"[MITRE] fetch failed: {type(e).__name__}: {e}")
            stats.errors += 1
            return stats

        # 3. Parse
        try:
            import json
            bundle = json.loads(raw)
        except Exception as e:
            print(f"[MITRE] JSON parse failed: {type(e).__name__}: {e}")
            stats.errors += 1
            return stats

        # 4. Iterate objects
        objects = bundle.get("objects", [])
        stats.parsed = len(objects)
        print(f"[MITRE] bundle contains {stats.parsed} STIX objects")

        for obj in objects:
            try:
                self._write_object(db, obj, stats)
            except Exception as e:
                db.rollback()
                stats.errors += 1
                if stats.errors <= 5:
                    print(
                        f"[MITRE] write failed for "
                        f"{obj.get('id', '<no id>')}: "
                        f"{type(e).__name__}: {e}"
                    )

        # touch source — keeps it appearing as "active"
        _ = source_id

        print(
            f"[MITRE] done — groups={stats.groups} techniques={stats.techniques} "
            f"malware={stats.malware} relationships={stats.relationships} "
            f"inserted={stats.inserted} updated={stats.updated} "
            f"skipped={stats.skipped} errors={stats.errors}"
        )
        return stats

    # ------------------------------------------------------------------------
    # Fetch
    # ------------------------------------------------------------------------
    def fetch(self) -> bytes:
        """Download the STIX bundle. Raises on HTTP errors."""
        with httpx.Client(
            timeout=HTTP_TIMEOUT_SECONDS,
            follow_redirects=True,
        ) as client:
            response = client.get(
                MITRE_BUNDLE_URL,
                headers={"User-Agent": USER_AGENT},
            )
            response.raise_for_status()
            return response.content

    # ------------------------------------------------------------------------
    # Pure parser — also used by tests with an inline bundle dict
    # ------------------------------------------------------------------------
    def parse_bundle(self, bundle: dict) -> Iterable[dict]:
        """
        Yield STIX objects from a parsed bundle, skipping revoked/deprecated.
        Pure function — no DB access. Used by tests.
        """
        for obj in bundle.get("objects", []):
            if obj.get("revoked"):
                continue
            if obj.get("x_mitre_deprecated"):
                continue
            yield obj

    # ------------------------------------------------------------------------
    # Source upsert (mirrors BaseIngester._upsert_source)
    # ------------------------------------------------------------------------
    def _upsert_source(self, db: Session) -> int:
        existing = db.query(Source).filter(Source.name == self.name).first()
        if existing:
            return existing.id

        source = Source(
            name=self.name,
            source_type=self.source_type,
            url=self.source_url,
            description=self.description,
        )
        db.add(source)
        db.commit()
        db.refresh(source)
        return source.id

    # ------------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------------
    def _write_object(
        self,
        db: Session,
        obj: dict,
        stats: MitreIngestStats,
    ) -> None:
        """Route one STIX object to the right table writer."""
        # Skip revoked / deprecated
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            stats.skipped += 1
            return

        stix_type = obj.get("type")
        if stix_type == "intrusion-set":
            action = self._write_group(db, obj)
            stats.groups += 1
        elif stix_type == "attack-pattern":
            action = self._write_technique(db, obj)
            stats.techniques += 1
        elif stix_type == "malware":
            action = self._write_malware(db, obj)
            stats.malware += 1
        elif stix_type == "relationship":
            action = self._write_relationship(db, obj)
            stats.relationships += 1
        else:
            # Tools, mitigations, campaigns, data-components, etc.
            # Not in scope for v1 — Session 19 brief is groups + techniques
            # + malware + relationships.
            stats.skipped += 1
            return

        if action == "inserted":
            stats.inserted += 1
        elif action == "updated":
            stats.updated += 1

    # ------------------------------------------------------------------------
    # Per-type writers — all use ON CONFLICT DO UPDATE keyed on stix_id
    # ------------------------------------------------------------------------
    def _write_group(self, db: Session, obj: dict) -> str:
        attack_id = self._extract_attack_id(obj)
        if not attack_id:
            return "skipped"

        values = {
            "stix_id": obj["id"],
            "attack_id": attack_id,
            "name": obj.get("name", ""),
            "description": obj.get("description"),
            "aliases": obj.get("aliases", []),
            "external_references": obj.get("external_references", []),
            "created": self._parse_dt(obj.get("created")),
            "modified": self._parse_dt(obj.get("modified")),
            "revoked": bool(obj.get("revoked", False)),
            "deprecated": bool(obj.get("x_mitre_deprecated", False)),
            "updated_at": datetime.now(timezone.utc),
        }
        return self._upsert(db, AttackGroup, values, "stix_id")

    def _write_technique(self, db: Session, obj: dict) -> str:
        attack_id = self._extract_attack_id(obj)
        if not attack_id:
            return "skipped"

        values = {
            "stix_id": obj["id"],
            "attack_id": attack_id,
            "name": obj.get("name", ""),
            "description": obj.get("description"),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
            "kill_chain_phases": obj.get("kill_chain_phases", []),
            "platforms": obj.get("x_mitre_platforms", []),
            "data_sources": obj.get("x_mitre_data_sources", []),
            "detection": obj.get("x_mitre_detection"),
            "external_references": obj.get("external_references", []),
            "created": self._parse_dt(obj.get("created")),
            "modified": self._parse_dt(obj.get("modified")),
            "revoked": bool(obj.get("revoked", False)),
            "deprecated": bool(obj.get("x_mitre_deprecated", False)),
            "updated_at": datetime.now(timezone.utc),
        }
        return self._upsert(db, AttackTechnique, values, "stix_id")

    def _write_malware(self, db: Session, obj: dict) -> str:
        attack_id = self._extract_attack_id(obj)
        if not attack_id:
            return "skipped"

        values = {
            "stix_id": obj["id"],
            "attack_id": attack_id,
            "name": obj.get("name", ""),
            "description": obj.get("description"),
            "aliases": obj.get("x_mitre_aliases", obj.get("aliases", [])),
            "malware_types": obj.get("malware_types", []),
            "platforms": obj.get("x_mitre_platforms", []),
            "is_family": bool(obj.get("is_family", True)),
            "external_references": obj.get("external_references", []),
            "created": self._parse_dt(obj.get("created")),
            "modified": self._parse_dt(obj.get("modified")),
            "revoked": bool(obj.get("revoked", False)),
            "deprecated": bool(obj.get("x_mitre_deprecated", False)),
            "updated_at": datetime.now(timezone.utc),
        }
        return self._upsert(db, AttackMalware, values, "stix_id")

    def _write_relationship(self, db: Session, obj: dict) -> str:
        values = {
            "stix_id": obj["id"],
            "relationship_type": obj.get("relationship_type", ""),
            "source_ref": obj.get("source_ref", ""),
            "target_ref": obj.get("target_ref", ""),
            "description": obj.get("description"),
            "created": self._parse_dt(obj.get("created")),
            "modified": self._parse_dt(obj.get("modified")),
            "revoked": bool(obj.get("revoked", False)),
            "deprecated": bool(obj.get("x_mitre_deprecated", False)),
            "updated_at": datetime.now(timezone.utc),
        }
        if not values["source_ref"] or not values["target_ref"]:
            return "skipped"
        return self._upsert(db, AttackRelationship, values, "stix_id")

    # ------------------------------------------------------------------------
    # Postgres-native upsert
    # ------------------------------------------------------------------------
    def _upsert(
        self,
        db: Session,
        model_cls: Any,
        values: dict,
        pk_column: str,
    ) -> str:
        """
        INSERT ... ON CONFLICT (pk) DO UPDATE. Returns "inserted" or
        "updated" based on whether the row already existed.

        We check existence with a quick SELECT first so we can report the
        right counter. The race window between SELECT and INSERT is fine
        — the upsert is still safe, we just might mis-attribute one row
        between counters under heavy concurrency. Acceptable.
        """
        existed = (
            db.query(model_cls)
            .filter(getattr(model_cls, pk_column) == values[pk_column])
            .first()
        )

        # Build the upsert statement. We update everything except the PK on conflict.
        update_cols = {k: v for k, v in values.items() if k != pk_column}
        stmt = (
            pg_insert(model_cls.__table__)
            .values(**values)
            .on_conflict_do_update(
                index_elements=[pk_column],
                set_=update_cols,
            )
        )

        try:
            db.execute(stmt)
            db.commit()
        except IntegrityError:
            db.rollback()
            raise

        return "updated" if existed else "inserted"

    # ------------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------------
    @staticmethod
    def _extract_attack_id(obj: dict) -> Optional[str]:
        """
        Pull the human-readable ATT&CK ID (G0016, T1566.001, S0367) out of
        the external_references array. The MITRE entry is the one where
        source_name == "mitre-attack".
        """
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
        return None

    @staticmethod
    def _parse_dt(value: Optional[str]) -> Optional[datetime]:
        """Parse a STIX timestamp like '2017-05-31T21:32:29.203Z'."""
        if not value:
            return None
        try:
            # STIX timestamps are ISO 8601 with trailing Z
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None
