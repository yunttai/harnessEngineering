# 기술 부채 트래커

| ID | 설명 | 심각도 | 상태 | 선행 계획 |
| --- | --- | --- | --- | --- |
| TD-001 | local-copy sandbox가 OS 보안 경계가 아님 | high | resolved (Docker opt-in) | MVP 3 |
| TD-002 | 내장 patcher가 단순한 단일 파일 CWE-89만 지원 | high | resolved (CWE-22/78/502 narrow AST 추가) | 운영 하드닝 |
| TD-003 | Trivy/Gitleaks/SARIF parser 미구현 | medium | resolved | MVP 2 |
| TD-004 | GitHub App PR provider 미구현 | medium | resolved | MVP 2 |
| TD-005 | PostgreSQL persistent store 미구현 | low | open | 이후 |
| TD-006 | 인증/인가 context graph 미구현 | high | open | 연구 단계 |
| TD-007 | DAST differential oracle 미구현 | high | resolved | MVP 3 |
| TD-008 | external LLM structured output provider 미구현 | medium | resolved | MVP 2 |
| TD-009 | 코드 오케스트레이터의 verification feedback 기반 자동 재패치 계약 미구현 | medium | resolved | MVP 2 |
| TD-010 | GitHub App 실제 credential/권한 smoke test 미실행 | medium | open (manual workflow ready) | 운영 secret 필요 |
| TD-011 | 배포 후 관측 기반 자동 rollback 판단 미구현 | high | resolved (bounded observation) | 운영 하드닝 |
| TD-012 | Docker/ZAP/Nuclei 실제 daemon/image smoke 미실행 | high | resolved (local Docker) | MVP 3 |
| TD-013 | 고정 Docker image digest의 다중 OS/architecture CI matrix 미구현 | medium | resolved (workflow added; remote run pending) | 운영 하드닝 |
| TD-014 | unsafe pickle 데이터의 schema 기반 migration 자동화 미구현 | high | open | 사람 검토/후속 연구 |
