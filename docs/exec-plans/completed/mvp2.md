# 실행 계획: MVP 2 — Multi Scanner와 GitHub PR

- 상태: DONE
- 생성일: 2026-08-11
- 소유자: orchestrator
- 완료 기준: Semgrep/Trivy/Gitleaks/SARIF 결과 정규화와 verified draft PR 생성 경계가
  fixture·임시 Git·mock GitHub 테스트로 검증되고 `bash scripts/check.sh`가 통과한다.

## 배경

MVP 1의 단일 scanner/결정적 patcher 루프를 여러 scanner, strict LLM 후보, bounded feedback,
verified-only Git/GitHub App 전달로 확장한다.

## 범위와 비범위

- 범위: Trivy/Gitleaks/SARIF parser, 다중 patch provider ranking, feedback retry, local Git,
  GitHub App draft PR, PR evidence/CI link, RunMetrics
- 비범위: 실제 production deploy, 무허가 원격 DAST, GitHub App 실계정 smoke test,
  Docker/VM security boundary

## 단계별 체크리스트

- [x] Semgrep adapter
- [x] Trivy parser
- [x] Gitleaks parser
- [x] SARIF common parser
- [x] candidate ranking 다중 provider
- [x] local Git publisher 강화
- [x] Codex/OpenCode/Claude local CLI structured-output provider
- [x] verification feedback bounded retry
- [x] GitHub App provider
- [x] draft PR evidence template와 CI status link
- [x] aggregate RunMetrics

## 검증 명령

```bash
bash scripts/check.sh
bash attack2patch/scripts/demo.sh
```

결과: 2026-08-11 기준 38 tests passed, 데모 patch score 100, post-patch Finding 0건.
Codex CLI와 Claude CLI는 실제 인증 세션으로 dry-run하여 각각 구조화 후보 생성과 VERIFIED
검증까지 통과했다. 현재 개발 환경에 설치되지 않은 OpenCode CLI는 동일 provider 계약의 mock
JSONL event 테스트로 검증했다.

## 위험과 rollback

- 외부 scanner binary와 실제 GitHub credential은 환경별 차이가 있으므로 기본 비활성/optional이다.
- publish 실패 시 자동 reset하지 않고 생성 branch와 evidence를 보존해 사람이 복구한다.
- 회귀 시 해당 변경 commit을 revert하고 VERIFIED artifact는 삭제하지 않는다.

## 진행 로그

- 2026-08-11: parser, LLM, feedback, metrics 구현
- 2026-08-11: local Git 통합과 GitHub App mock PR 검증
- 2026-08-11: 필수 check 및 end-to-end demo 통과
- 2026-08-11: OpenAI HTTP provider를 Codex/OpenCode/Claude local CLI provider로 교체하고
  Codex/Claude 실제 dry-run 통과

## 결정 기록

- LLM 출력은 선택한 local CLI의 구조화 출력 뒤 Pydantic과 로컬 hash/range 검증을 다시 거친다.
- push와 PR은 branch/commit과 분리된 설정·CLI 게이트로 유지한다.

## 남은 기술 부채

- `../tech-debt-tracker.md`의 TD-001, TD-002, TD-010을 따른다.
