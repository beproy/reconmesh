"""
seed_domains.py — load a CSV of domain names into ReconMesh's `domains` table.

Usage (run inside the backend container):
    docker compose exec backend python scripts/seed_domains.py /app/seed_data/<file>.csv

CSV format (header required):
    name,notes
    example.com,Some optional context
    api.example.com,

Behavior:
    - Domain names are lowercased and stripped before insert.
    - The `notes` column is read but NOT stored in the database — it's only
      for the human reading the CSV. The schema doesn't have a free-text
      notes column on `domains` (analyst notes go in the `notes` table,
      which links to specific evidence).
    - TLD is derived from the domain name when not present.
    - Domains that already exist are skipped (idempotent).
    - The script never updates or deletes existing rows.
    - Empty rows and rows with blank `name` are skipped.

The script is intentionally generic — it has no hardcoded references to any
specific organization. Drop any CSV in this format and it will load.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

# Make backend modules importable when run as a script
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy.exc import IntegrityError

from database import SessionLocal
from models import Domain


def load_seed_csv(csv_path: Path) -> dict[str, int]:
    """
    Load a seed CSV and insert any new domains. Returns a counter dict.
    """
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV not found: {csv_path}")

    stats = {"read": 0, "inserted": 0, "skipped_existing": 0, "skipped_blank": 0, "errors": 0}

    db = SessionLocal()
    try:
        with csv_path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)

            if "name" not in (reader.fieldnames or []):
                raise ValueError(
                    f"CSV must have a 'name' column. Found: {reader.fieldnames}"
                )

            for row in reader:
                stats["read"] += 1
                raw_name = (row.get("name") or "").strip().lower()

                if not raw_name:
                    stats["skipped_blank"] += 1
                    continue

                # Already exists? Skip without touching anything.
                existing = db.query(Domain).filter(Domain.name == raw_name).first()
                if existing is not None:
                    stats["skipped_existing"] += 1
                    continue

                # Derive TLD from the name
                tld = raw_name.rsplit(".", 1)[-1] if "." in raw_name else None

                domain = Domain(name=raw_name, tld=tld)
                db.add(domain)
                try:
                    db.commit()
                    stats["inserted"] += 1
                except IntegrityError:
                    # Race condition or duplicate within the same CSV — treat as skip
                    db.rollback()
                    stats["skipped_existing"] += 1
                except Exception as e:
                    db.rollback()
                    stats["errors"] += 1
                    print(f"  ERROR on '{raw_name}': {type(e).__name__}: {e}")
    finally:
        db.close()

    return stats


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        print("\nERROR: exactly one argument required (the CSV path).")
        return 2

    csv_path = Path(sys.argv[1])
    print(f"Loading domains from {csv_path}...")

    try:
        stats = load_seed_csv(csv_path)
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        return 1
    except ValueError as e:
        print(f"ERROR: {e}")
        return 1

    print()
    print("Done.")
    print(f"  Rows read:           {stats['read']}")
    print(f"  Inserted:            {stats['inserted']}")
    print(f"  Skipped (existing):  {stats['skipped_existing']}")
    print(f"  Skipped (blank):     {stats['skipped_blank']}")
    print(f"  Errors:              {stats['errors']}")
    return 0 if stats["errors"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
