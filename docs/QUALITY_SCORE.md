# 품질 등급

| 영역 | 현재 등급 | 목표 | 근거 |
| --- | --- | --- | --- |
| 문서 | A | A | PRD, 설계, 위협, API, DB, 실행 문서 동기화 |
| 공격 탐지 | B | B | 5개 fixture/정상값, schema, redaction, 자동 log tail 테스트 |
| 패치 검증 | B | B | AST mapping, hash+Diff 승인, 5개 fail-closed 검증 E2E |
| 배포 및 롤백 | B | B | 승인 gate, build 무영향, 성공/자동/수동 rollback adapter 테스트 |
| UI | B | B | API 상태 gate와 DOM `data-testid`/disabled E2E 테스트 |

## 자동 증거

- `scripts/check.sh`: 22 tests, compileall, Ruff, architecture, secret scan
- `docker compose --project-name attack2patch config --quiet`: localhost port, named volume, internal socket 검증
- live candidate image `attack2patch-demo:9df492ce70a0`: health/normal/5개 attack 성공, 전체 5.767초
- live manual rollback 2.666초, automatic rollback rehearsal 7.156초와 baseline health 성공
