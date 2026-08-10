from typing import Protocol

from attack2patch.types.attack_event import AttackEvent


class EventRepository(Protocol):
    def save(self, event: AttackEvent) -> None: ...

    def get(self, event_id: str) -> AttackEvent | None: ...
