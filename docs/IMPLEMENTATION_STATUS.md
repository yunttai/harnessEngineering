# 구현 상태 매트릭스

원본 계획서(`references/source-project-plan.md`)의 범위를 현재 코드와 연결한 상태표입니다.
`IMPLEMENTED`는 저장소 코드와 테스트가 존재함을, `SCAFFOLDED`는 인터페이스·정책·Agent만
있음을, `PLANNED`는 실행 계획/기술 부채에만 있음을 뜻합니다.

| 계획 영역 | 상태 | 현재 구현 | 다음 단계 |
| --- | --- | --- | --- |
| Harness map/knowledge base | IMPLEMENTED | AGENTS, ARCHITECTURE, docs, agent prompts, checks | 문서 gardening 자동 PR |
| Detection Harness | IMPLEMENTED | Python AST, Semgrep, Trivy, Gitleaks, SARIF parser | CodeQL DB 실행 adapter |
| Finding normalization | IMPLEMENTED | Pydantic Finding, fingerprint, evidence merge | cross-scanner correlation 개선 |
| Root-cause analysis | IMPLEMENTED | deterministic analyzer와 OpenAI strict structured output provider | interprocedural data-flow |
| Patch generation | IMPLEMENTED (limited) | CWE-89 codemod + schema-validated LLM TextEdit provider | framework codemod 확대 |
| Patch scoring | IMPLEMENTED | Security 40, Regression 30, Size 15, Build 10, Style 5 | 프로젝트별 가중치 profile |
| Build verification | IMPLEMENTED | Python compileall | 언어/빌드 시스템 adapter |
| Functional verification | IMPLEMENTED | 명시적 `--execute-tests` pytest | JUnit/Jest/Playwright adapter |
| Security re-scan | IMPLEMENTED | 동일 CWE/rule 재탐지 검사 | 원 scanner 우선 replay, SARIF correlation |
| Exploit verification | IMPLEMENTED (CWE-89) | manifest command + AST parameterization oracle | DAST differential replay |
| Verification feedback re-patch | IMPLEMENTED | stage evidence 기반 provider feedback와 bounded retry | benchmark tuning |
| Evidence/artifacts | IMPLEMENTED | JSON/JSONL/diff, best-effort redaction | PostgreSQL/object storage |
| CLI/API | IMPLEMENTED | Typer CLI, local FastAPI boundary | job queue, auth, concurrency controls |
| Git branch/commit | IMPLEMENTED | verified-only publish service, clean tree, intended files, gates | worktree 기반 원자적 실패 복구 |
| Pull Request | IMPLEMENTED | GitHub App installation token, draft PR evidence body | live credential smoke test |
| Staging/Canary/Production | SCAFFOLDED | argv provider와 rollback runbook, 기본 off | environment별 readiness/관측 adapter |
| Docker/VM security boundary | PLANNED | local-copy verifier만 제공 | Docker/Firecracker sandbox |
| Aggregate evaluation metrics | IMPLEMENTED | RunMetrics 집계 | benchmark runner/dashboard |

## 현재 완료 기준

- `bash scripts/check.sh` 통과
- 내장 CWE-89 예제가 dry-run에서 원본을 보존
- 검증된 후보만 `--apply` 시 적용
- 패치 후 일반 테스트, 보안 manifest, 재스캔, 구조 oracle 통과
- 패치 후 동일 내장 Finding 0건
- 외부 scanner 미설치는 성공으로 숨기지 않고 `SKIPPED` evidence로 기록

## Production 전 필수 선행 작업

1. local-copy 대신 실제 보안 격리 경계 도입
2. 실제 GitHub App credential을 사용한 smoke test와 운영 권한 검토
3. 외부 scanner binary별 version matrix 통합 테스트
4. staging/canary 배포 후 관측과 자동 rollback 판단 연결
