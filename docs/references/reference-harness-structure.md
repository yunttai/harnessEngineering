# 기준 Harness 레포지토리 구조 요약

- 기준: `maxoverpro/harness`
- 확인일: 2026-08-11

채택한 패턴:

1. 루트 `AGENTS.md`는 짧은 목차/맵으로 유지
2. 루트 `ARCHITECTURE.md`는 최상위 불변 조건 기록
3. `docs/`를 코드 외 지식의 단일 기록 시스템으로 사용
4. `.opencode/agent/`에 역할별 primary/subagent 정의
5. `docs/product-specs/`, `design-docs/`, `exec-plans/`, `generated/`, `references/` 분리
6. `scripts/check.sh`를 전체 기계 검증 진입점으로 사용
7. `.github/workflows/harness.yml`에서 동일 검증 실행
8. reviewer/security/committer/deployer의 권한과 책임 분리

본 저장소에서는 위 구조를 보안 자동 패치 도메인에 맞게 확장해 detector, analyzer, patcher,
verifier를 독립 Agent로 추가하고 실제 Python MVP 코드를 같은 레이어 맵에 배치했습니다.
