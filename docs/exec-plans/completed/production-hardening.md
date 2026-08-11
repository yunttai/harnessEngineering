# 실행 계획: 운영 하드닝과 결정적 패처 확장

- 상태: COMPLETED
- 생성일: 2026-08-12
- 완료일: 2026-08-12
- 소유자: orchestrator
- 완료 기준: 고정 digest Docker smoke matrix, 선택적 GitHub App credential smoke,
  관측 실패 자동 rollback, CWE-22/78/502의 좁고 결정적인 패치와 실제 production promotion이
  실행 evidence로 검증되고 `bash scripts/check.sh`가 통과한다.

## 배경

MVP 3 이후 남아 있던 운영 CI, 실제 외부 scanner, canary 이후 관측, CWE-89 외 결정적 패치와
production promotion 경로를 완료했다.

## 범위와 비범위

- 범위: linux/amd64·linux/arm64 Docker matrix, digest pin 검사, 선택적 GitHub App 무변경 smoke,
  bounded observation loop와 rollback, Python CWE-22/78/502의 안전한 좁은 AST 패턴,
  실제 Semgrep/Trivy/Gitleaks/Codex/Docker deployment 실행
- 비범위: credential 생성·저장, 조직별 cloud credential/endpoint 생성, pickle 데이터의 자동 migration,
  인증/인가·IDOR·비즈니스 로직 자동 수정

## 완료 체크리스트

- [x] Docker image digest 고정과 amd64/arm64 smoke workflow
- [x] GitHub App installation/repository/permission read-only smoke(선택적 PR 기능)
- [x] canary 이후 bounded observation과 실패 rollback
- [x] CWE-78 subprocess shell f-string→argv 패처
- [x] CWE-502 unsafe YAML loader→safe_load 패처
- [x] CWE-22 Flask safe directory send 패처
- [x] schema·문서·전체 하네스 갱신
- [x] Semgrep/Trivy/Gitleaks digest-pinned Docker 실제 실행
- [x] 인증된 Codex CLI 실제 structured candidate 생성
- [x] pushed commit evidence gate와 production promotion phase
- [x] 실제 Docker staging/canary/관측/promotion 배포

## 검증 명령

```bash
bash scripts/check.sh
python attack2patch/scripts/docker-smoke.py --expected-arch amd64
attack2patch github-app-smoke --repository OWNER/REPOSITORY
```

## 위험과 rollback

- Docker ARM runner 가용성 실패를 기능 PASS로 숨기지 않는다.
- GitHub App smoke는 PR 기능을 명시적으로 사용할 때만 installation token을 발급한다.
- 관측 command 실패·timeout은 즉시 rollback하며 성공으로 간주하지 않는다.
- 결정적 패처는 AST shape와 API가 정확히 일치하지 않으면 후보를 생성하지 않는다.
- 회귀 시 변경 commit을 revert하고 기존 run evidence는 보존한다.

## 실행 evidence

- 2026-08-12: pinned digest 로컬 amd64 Docker smoke 통과(ZAP 6, Nuclei 1→0)
- 2026-08-12: production profile의 builtin/Semgrep/Trivy/Gitleaks errors 0, skipped 0
- 2026-08-12: full orchestrator Docker E2E APPLIED, SQLite exploit과 Nuclei 1→0 검증
- 2026-08-12: 캐시된 ChatGPT 로그인으로 Codex CLI structured patch 후보 실제 생성
- 2026-08-12: `Attack2patch` commit push 후 staging/canary 6회 관측/production promotion 완료
- 2026-08-12: live SQLi 요청 `count=0`, product API container `/health` 200 확인
- 2026-08-12: rootless Linux Docker에서 임시 workspace 권한 문제 재현·수정 후 smoke 통과
- 2026-08-12: 전체 하네스 72 tests, architecture/config/policy/schema/link/secret 검사 통과

## 결정 기록

- Docker tag가 아니라 multi-architecture manifest digest를 설정과 CI에서 동일하게 사용한다.
- GitHub App은 draft PR을 요청한 경우에만 필요하며 기본 commit/push 흐름에는 필요하지 않다.
- unsafe pickle은 데이터 migration 없이는 안전한 의미 보존이 불가능하므로 자동 패치하지 않는다.

## 남은 환경별 작업

- 조직별 cloud production endpoint와 관측 backend를 사용할 때는 해당 command와 rollback runbook을
  운영 담당자가 승인해야 한다. 제품의 command provider와 fail-closed gate는 이를 강제한다.
