# 구현 상태 매트릭스

원본 계획서(`references/source-project-plan.md`)의 범위를 현재 코드와 연결한 상태표입니다.
`IMPLEMENTED`는 저장소 코드와 테스트가 존재함을, `SCAFFOLDED`는 인터페이스·정책·Agent만
있음을, `PLANNED`는 실행 계획/기술 부채에만 있음을 뜻합니다.

| 계획 영역 | 상태 | 현재 구현 | 다음 단계 |
| --- | --- | --- | --- |
| Harness map/knowledge base | IMPLEMENTED | AGENTS, ARCHITECTURE, docs, agent prompts, checks | 문서 gardening 자동 PR |
| Detection Harness | IMPLEMENTED | Python AST와 digest-pinned Docker Semgrep/Trivy/Gitleaks 실제 실행, SARIF parser | CodeQL DB 실행 adapter |
| Finding normalization | IMPLEMENTED | Pydantic Finding, fingerprint, evidence merge | cross-scanner correlation 개선 |
| Root-cause analysis | IMPLEMENTED | deterministic analyzer와 Codex/OpenCode/Claude CLI structured-output provider | interprocedural data-flow |
| Patch generation | IMPLEMENTED (limited) | Codex/OpenCode/Claude + 좁은 CWE-22/78/89/502 Python AST 패처 | framework/언어 codemod 확대, pickle migration은 사람 검토 |
| Patch scoring | IMPLEMENTED | Security 40, Regression 30, Size 15, Build 10, Style 5 | 프로젝트별 가중치 profile |
| Build verification | IMPLEMENTED | Python compileall | 언어/빌드 시스템 adapter |
| Functional verification | IMPLEMENTED | 명시적 `--execute-tests` pytest | JUnit/Jest/Playwright adapter |
| Security re-scan | IMPLEMENTED | 동일 CWE/rule 재탐지 검사 | 원 scanner 우선 replay, SARIF correlation |
| Exploit verification | IMPLEMENTED | strict manifest/DAST differential + CWE-22/78/89/502 독립 AST oracle | live exploit corpus 확대 |
| Verification feedback re-patch | IMPLEMENTED | stage evidence 기반 provider feedback와 bounded retry | benchmark tuning |
| Evidence/artifacts | IMPLEMENTED | JSON/JSONL/diff, best-effort redaction | PostgreSQL/object storage |
| CLI/API | IMPLEMENTED | Typer scan/run/publish/dast/deploy/github-app-smoke, local FastAPI dry-run boundary | job queue와 API auth |
| Git branch/commit/push | IMPLEMENTED | publish 기본 `Attack2patch` branch, selected-file commit, origin push | worktree 기반 원자적 실패 복구 |
| Pull Request | IMPLEMENTED | GitHub App installation/repository/permission smoke와 draft PR | 실제 repository secret으로 수동 smoke 실행 |
| Staging/Canary/Production | IMPLEMENTED | pushed commit gate, 실제 Docker staging→canary→bounded observation→production promotion, 첫 실패/timeout/한도 소진 rollback | 환경별 command/runbook 검토 |
| Docker security boundary | IMPLEMENTED (opt-in) | digest-pinned read-only 격리와 cleanup; 로컬 Linux smoke 및 원격 amd64/arm64 CI 성공 | remote runner 정기 회귀 감시 |
| DAST | IMPLEMENTED (opt-in) | digest-pinned ZAP/Nuclei, exact authorization와 differential; amd64/arm64 CI 성공 | exploit corpus 확대 |
| Aggregate evaluation metrics | IMPLEMENTED | RunMetrics 집계 | benchmark runner/dashboard |

## 현재 완료 기준

- `bash scripts/check.sh` 통과
- 내장 CWE-89 예제가 dry-run에서 원본을 보존
- 검증된 후보만 `--apply` 시 적용
- 패치 후 일반 테스트, 보안 manifest, 재스캔, 구조 oracle 통과
- 패치 후 동일 내장 Finding 0건
- 운영 프로필에서 외부 scanner 네 종류 모두 실행되며 누락/error는 run 실패
- 실제 SQLite exploit과 Nuclei finding이 baseline 1건→patched 0건임을 evidence로 기록
- pushed `Attack2patch` commit만 staging/canary/관측/promotion에 진입

## 조직별 운영 환경 연결 시 필요한 작업

1. draft PR 기능을 사용할 경우에만 repository secret으로 GitHub App smoke 수행
2. 실제 조직의 production endpoint/관측 backend에 맞춘 command와 rollback runbook 승인
