import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from uuid import UUID

from attack2patch.types.attack_event import AttackEvent
from attack2patch.types.deployment import Deployment, DeploymentStatus
from attack2patch.types.finding import CodeFinding
from attack2patch.types.patch import PatchCandidate


class SQLiteRepository:
    """SQLite-backed history store for the single-node MVP."""

    def __init__(self, database_url: str) -> None:
        if not database_url.startswith("sqlite:///"):
            raise ValueError("only sqlite:/// database URLs are supported")
        database_name = database_url.removeprefix("sqlite:///")
        if not database_name:
            raise ValueError("database path must not be empty")
        if database_name != ":memory:":
            database_path = Path(database_name)
            database_path.parent.mkdir(parents=True, exist_ok=True)
            database_name = str(database_path)
        self._connection = sqlite3.connect(database_name, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._lock = RLock()
        self._initialize()

    def _initialize(self) -> None:
        with self._lock, self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS attack_events (
                    id TEXT PRIMARY KEY,
                    detected_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    data TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS code_findings (
                    id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL REFERENCES attack_events(id),
                    data TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS patch_candidates (
                    id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL REFERENCES code_findings(id),
                    status TEXT NOT NULL,
                    data TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS deployments (
                    id TEXT PRIMARY KEY,
                    patch_id TEXT NOT NULL REFERENCES patch_candidates(id),
                    status TEXT NOT NULL,
                    deployed_at TEXT,
                    data TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS state_transitions (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    event_id TEXT,
                    occurred_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error TEXT
                );
                """
            )

    @staticmethod
    def _identifier(value: str | UUID) -> str:
        return str(value)

    def _transition(
        self,
        entity_type: str,
        entity_id: str | UUID,
        status: str,
        *,
        event_id: str | UUID | None = None,
        error: str | None = None,
    ) -> None:
        self._connection.execute(
            """
            INSERT INTO state_transitions
                (entity_type, entity_id, event_id, occurred_at, status, error)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                entity_type,
                self._identifier(entity_id),
                self._identifier(event_id) if event_id else None,
                datetime.now(timezone.utc).isoformat(),
                status,
                error,
            ),
        )

    def save(self, event: AttackEvent | Deployment) -> None:
        if isinstance(event, AttackEvent):
            self.save_event(event)
        elif isinstance(event, Deployment):
            self.save_deployment(event)
        else:
            raise TypeError(f"unsupported entity: {type(event).__name__}")

    def save_event(self, event: AttackEvent) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO attack_events (id, detected_at, status, data) VALUES (?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    detected_at=excluded.detected_at,
                    status=excluded.status,
                    data=excluded.data
                """,
                (str(event.id), event.detected_at.isoformat(), event.status.value, event.model_dump_json()),
            )
            self._transition("attack_event", event.id, event.status.value, event_id=event.id, error=event.error)

    def get(self, event_id: str | UUID) -> AttackEvent | None:
        row = self._connection.execute(
            "SELECT data FROM attack_events WHERE id = ?", (self._identifier(event_id),)
        ).fetchone()
        return AttackEvent.model_validate_json(row["data"]) if row else None

    def list_events(self) -> list[AttackEvent]:
        rows = self._connection.execute(
            "SELECT data FROM attack_events ORDER BY detected_at DESC"
        ).fetchall()
        return [AttackEvent.model_validate_json(row["data"]) for row in rows]

    def save_finding(self, finding: CodeFinding) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO code_findings (id, event_id, data) VALUES (?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET event_id=excluded.event_id, data=excluded.data
                """,
                (str(finding.id), str(finding.event_id), finding.model_dump_json()),
            )
            self._transition("code_finding", finding.id, "LOCATED", event_id=finding.event_id)

    def get_finding(self, finding_id: str | UUID) -> CodeFinding | None:
        row = self._connection.execute(
            "SELECT data FROM code_findings WHERE id = ?", (self._identifier(finding_id),)
        ).fetchone()
        return CodeFinding.model_validate_json(row["data"]) if row else None

    def findings_for_event(self, event_id: str | UUID) -> list[CodeFinding]:
        rows = self._connection.execute(
            "SELECT data FROM code_findings WHERE event_id = ? ORDER BY rowid",
            (self._identifier(event_id),),
        ).fetchall()
        return [CodeFinding.model_validate_json(row["data"]) for row in rows]

    def save_patch(self, patch: PatchCandidate) -> None:
        finding = self.get_finding(patch.finding_id)
        event_id = finding.event_id if finding else None
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO patch_candidates (id, finding_id, status, data) VALUES (?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    finding_id=excluded.finding_id,
                    status=excluded.status,
                    data=excluded.data
                """,
                (str(patch.id), str(patch.finding_id), patch.status.value, patch.model_dump_json()),
            )
            self._transition("patch_candidate", patch.id, patch.status.value, event_id=event_id)

    def get_patch(self, patch_id: str | UUID) -> PatchCandidate | None:
        row = self._connection.execute(
            "SELECT data FROM patch_candidates WHERE id = ?", (self._identifier(patch_id),)
        ).fetchone()
        return PatchCandidate.model_validate_json(row["data"]) if row else None

    def patches_for_event(self, event_id: str | UUID) -> list[PatchCandidate]:
        rows = self._connection.execute(
            """
            SELECT p.data
            FROM patch_candidates p
            JOIN code_findings f ON f.id = p.finding_id
            WHERE f.event_id = ?
            ORDER BY p.rowid
            """,
            (self._identifier(event_id),),
        ).fetchall()
        return [PatchCandidate.model_validate_json(row["data"]) for row in rows]

    def save_deployment(self, deployment: Deployment) -> None:
        patch = self.get_patch(deployment.patch_id)
        finding = self.get_finding(patch.finding_id) if patch else None
        event_id = finding.event_id if finding else None
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO deployments (id, patch_id, status, deployed_at, data)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    patch_id=excluded.patch_id,
                    status=excluded.status,
                    deployed_at=excluded.deployed_at,
                    data=excluded.data
                """,
                (
                    str(deployment.id),
                    str(deployment.patch_id),
                    deployment.status.value,
                    deployment.deployed_at.isoformat() if deployment.deployed_at else None,
                    deployment.model_dump_json(),
                ),
            )
            self._transition(
                "deployment",
                deployment.id,
                deployment.status.value,
                event_id=event_id,
                error=deployment.error,
            )

    def get_deployment(self, deployment_id: str | UUID) -> Deployment | None:
        row = self._connection.execute(
            "SELECT data FROM deployments WHERE id = ?", (self._identifier(deployment_id),)
        ).fetchone()
        return Deployment.model_validate_json(row["data"]) if row else None

    def deployments_for_patch(self, patch_id: str | UUID) -> list[Deployment]:
        rows = self._connection.execute(
            "SELECT data FROM deployments WHERE patch_id = ? ORDER BY rowid",
            (self._identifier(patch_id),),
        ).fetchall()
        return [Deployment.model_validate_json(row["data"]) for row in rows]

    def latest_completed_deployment(self) -> Deployment | None:
        row = self._connection.execute(
            """
            SELECT data FROM deployments
            WHERE status = ?
            ORDER BY deployed_at DESC, rowid DESC
            LIMIT 1
            """,
            (DeploymentStatus.COMPLETED.value,),
        ).fetchone()
        return Deployment.model_validate_json(row["data"]) if row else None

    def transitions_for_event(self, event_id: str | UUID) -> list[dict[str, str | None]]:
        rows = self._connection.execute(
            """
            SELECT entity_type, entity_id, occurred_at, status, error
            FROM state_transitions WHERE event_id = ? ORDER BY sequence
            """,
            (self._identifier(event_id),),
        ).fetchall()
        return [dict(row) for row in rows]

    def close(self) -> None:
        with self._lock:
            self._connection.close()
