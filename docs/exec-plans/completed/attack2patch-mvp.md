# Attack2Patch 3일 MVP 완료 기록

- 상태: COMPLETED
- 완료일: 2026-08-11
- PRD: `../../product-specs/attack2patch-prd.md`

## 구현 범위

- [x] 취약 Flask/SQLite baseline과 SQL Injection 재현
- [x] schema 기반 공유 JSON 로그 수집, 민감 키 마스킹, 5개 공격 탐지
- [x] Flask AST route 및 취약 SQL mapping
- [x] 원본 불변 Diff, patch 승인, 격리 workspace 적용과 manifest hash
- [x] syntax/unit/normal/5개 attack/static rescan 검증
- [x] SQLite event/finding/patch/deployment/transition history
- [x] 상태 기반 REST API와 dashboard test ID
- [x] approval-gated Docker/Compose adapter, 자동 및 수동 rollback

## 자동 검증 증거

- `scripts/check.sh`: 22 tests passed, compileall, Ruff, architecture, secret scan
- `docker compose --project-name attack2patch config --quiet`: 통과
- baseline health: HTTP 200, 정상 `alice` 1건, SQL Injection 2건 노출 재현
- 자동 log 수집: 공격 event가 5초 이내 `CODE_LOCATED`
- isolated patch 검증: 0.636초, 5개 gate 모두 성공
- 전체 live flow: 5.767초, `attack2patch-demo:9df492ce70a0`, `COMPLETED`
- candidate 검증: health/normal/5개 재공격 모두 성공
- 수동 rollback: 2.666초, `attack2patch-demo:baseline` 복구와 HTTP health 성공
- 자동 rollback rehearsal: 7.156초, candidate health 후 강제 verdict 실패,
  baseline health 성공, `ROLLED_BACK`

자동 rollback은 다음 명령으로 재현한다.

```bash
PYTHONPATH=src python scripts/verify_docker_rollback.py
```
