# Attack2Patch 코드 리딩 가이드

이 문서는 처음 저장소를 보는 개발자가 **어디서 실행이 시작되고, 각 기능이 어느 디렉터리와
파일에 구현되어 있으며, 어떤 테스트가 그 동작을 보장하는지** 빠르게 찾기 위한 지도입니다.
제품 요구사항은 [PRD](product-specs/PRD.md), 아키텍처 불변 조건은
[ARCHITECTURE.md](../ARCHITECTURE.md)가 기준이며, 이 문서는 코드 탐색 경로에 집중합니다.

## 1. 가장 짧은 읽기 순서

전체 구현을 따라가려면 다음 순서로 읽습니다.

1. [`attack2patch/src/autopatch/types/models.py`](../attack2patch/src/autopatch/types/models.py) — 파이프라인이 주고받는
   Finding, Patch, Verification, Run 데이터 모델
2. [`attack2patch/src/autopatch/providers/contracts.py`](../attack2patch/src/autopatch/providers/contracts.py) — scanner,
   analyzer, patcher, verifier, Git/PR/deploy 교체 지점
3. [`attack2patch/src/autopatch/config/settings.py`](../attack2patch/src/autopatch/config/settings.py) — 허가 범위와 자율성
   게이트를 포함한 설정 스키마
4. [`attack2patch/src/autopatch/runtime/factory.py`](../attack2patch/src/autopatch/runtime/factory.py) — 설정에 따라 실제
   provider를 조립하는 composition root
5. [`attack2patch/src/autopatch/service/orchestrator.py`](../attack2patch/src/autopatch/service/orchestrator.py) — 탐지부터
   후보 선택과 적용까지의 폐쇄형 루프
6. [`attack2patch/src/autopatch/runtime/verifier.py`](../attack2patch/src/autopatch/runtime/verifier.py) — 임시 복사본에서
   build, regression, re-scan, exploit mitigation을 수행하는 핵심 검증기
7. [`attack2patch/src/autopatch/ui/cli.py`](../attack2patch/src/autopatch/ui/cli.py) 또는
   [`attack2patch/src/autopatch/ui/api.py`](../attack2patch/src/autopatch/ui/api.py) — 사용자 입력과 정책 경계

특정 기능만 수정할 때는 아래의 [기능별 코드 매핑](#5-기능별-코드-매핑)에서 바로 해당 행을
찾습니다.

## 2. 저장소 디렉터리 구조

```text
harnessEngineering/
├── AGENTS.md                    저장소 목차, 작업·검증 규칙
├── ARCHITECTURE.md              파이프라인과 레이어 불변 조건
├── README.md                    제품/개발 하네스 경계와 시작점
├── .opencode/agent/             제품 개발 역할별 에이전트
├── docs/
│   ├── product-specs/           PRD와 기능 수용 기준
│   ├── design-docs/             아키텍처 결정 기록
│   ├── secure-coding/           CWE별 탐지·수정 원칙
│   ├── exec-plans/              활성/완료 계획과 기술 부채
│   ├── generated/               코드에서 생성한 스키마 문서
│   └── references/              원본 계획과 운영 참고 자료
├── scripts/                     저장소 맵·문서·전체 품질 검증
└── attack2patch/                독립 설치·실행 가능한 제품
    ├── pyproject.toml           Python 패키지, 의존성, CLI entry point
    ├── config/                  scope/autonomy/provider 설정
    ├── rules/                   Semgrep 규칙
    ├── schemas/                 Finding/RunReport JSON Schema
    ├── runbooks/                제품과 함께 배포하는 운영 계약
    ├── scripts/                 제품 검사·스키마 생성·데모
    ├── examples/                재현 가능한 CWE-89 대상 저장소
    ├── src/autopatch/           실제 제품 패키지
    └── tests/                   제품 단위·통합 성격 테스트
```

루트의 개발 하네스는 제품의 요구사항과 품질을 관리하고, `attack2patch/`는 상위 디렉터리 없이도
실행할 수 있습니다. 제품 배포나 실행 환경에는 `attack2patch/`만 전달하면 됩니다.

### `attack2patch/src/autopatch/` 상세 구조

```text
attack2patch/src/autopatch/
├── __main__.py                  `python -m autopatch` → CLI
├── types/
│   └── models.py                모든 경계의 Pydantic 모델과 상태 enum
├── config/
│   └── settings.py              YAML/env 로딩, 정책 조합 검증
├── providers/
│   └── contracts.py             provider Protocol 인터페이스
├── repo/
│   └── artifacts.py             run evidence 기록·조회·secret redaction
├── service/
│   ├── normalization.py         경로 정규화, fingerprint/finding ID
│   ├── detection.py             multi-scanner 실행, 오류 분리, 중복 제거
│   ├── analysis.py              결정적 root-cause 분석
│   ├── providers.py             여러 patch provider 후보 병합
│   ├── scoring.py               40/30/15/10/5 후보 점수
│   ├── metrics.py               run 단위 평가 지표 집계
│   ├── orchestrator.py          분석→패치→검증→피드백→선택 상태 머신
│   └── publishing.py            VERIFIED-only apply/branch/commit/push/PR 정책
├── runtime/
│   ├── factory.py               service와 runtime 구현 조립
│   ├── fs.py                    안전한 경로, hash, 소스 파일 순회
│   ├── command.py               argv 기반 timeout subprocess 실행
│   ├── builtin_scanner.py       Python AST 내장 scanner
│   ├── semgrep_scanner.py       Semgrep JSON adapter
│   ├── external_scanners.py     SARIF/Trivy/Gitleaks parser와 adapter
│   ├── builtin_patcher.py       CWE-89 parameterized-query 패처
│   ├── cli_llm_provider.py      Codex/OpenCode/Claude CLI 분석·패치 adapter
│   ├── patch_apply.py           hash를 확인하는 TextEdit 적용기
│   ├── verifier.py              임시 복사본 4단계 검증
│   ├── git_publisher.py         로컬 Git branch/commit/push adapter
│   ├── github_publisher.py      GitHub App token/draft PR adapter
│   └── deployment.py            staging/canary/rollback 명령 adapter
└── ui/
    ├── common.py                로컬 target와 DAST 허가 검증
    ├── cli.py                   scan/run/publish/serve 명령
    └── api.py                   health/scan/run/run-status FastAPI 경계
```

`__init__.py` 파일은 주로 각 레이어의 공개 타입과 구현을 다시 export합니다. 구현을 찾을 때는
위 표의 실제 모듈부터 읽는 편이 빠릅니다.

## 3. 레이어를 읽는 방법

코드 의존성은 다음 순서를 지킵니다.

```text
Types → Config → Repo → Service → Runtime → UI
          ↑
       Providers
```

이 화살표는 **허용되는 import 방향**을 나타냅니다. 런타임 호출은 사용자가 UI를 호출한 뒤
반대 방향으로 내려가며, `runtime/factory.py`가 service에 runtime 구현을 Protocol로 주입합니다.

| 레이어 | 판단 또는 부작용 | 읽을 때 확인할 질문 |
| --- | --- | --- |
| `types` | 데이터 계약만 담당 | 어떤 상태와 evidence가 다음 단계로 전달되는가? |
| `config` | 입력 설정과 정책 조합 검증 | 어떤 동작이 기본 off이며 무엇을 명시적으로 허용해야 하는가? |
| `providers` | 구현 교체용 Protocol | 새 도구가 만족해야 하는 최소 메서드는 무엇인가? |
| `repo` | evidence 파일 I/O | 성공과 실패가 어디에 어떤 스키마로 보존되는가? |
| `service` | 순수한 선택·상태·게이트 판단 | 후보가 왜 선택/탈락하고 언제 재시도되는가? |
| `runtime` | AST, filesystem, subprocess, HTTP, Git | 실제 도구는 어떤 timeout과 안전 검사를 거치는가? |
| `ui` | CLI/API 사용자 경계 | 입력 경로와 실행 권한이 어디서 차단되는가? |

외부 scanner, LLM, GitHub 응답은 runtime 경계에서 공통 Pydantic 모델로 바뀐 뒤 service로
전달됩니다. Service 코드가 특정 CLI 명령이나 HTTP 응답 형식을 직접 해석하면 레이어 위반입니다.

## 4. 실행 흐름

### `scan`/`run` 흐름

```text
CLI `scan`/`run` 또는 API `/v1/scan`/`/v1/run`
  → ui.common.validate_target
  → config.load_settings
  → runtime.factory.build_orchestrator
  → service.detection.DetectionService.scan
      → runtime의 각 Scanner
      → service.normalization 기반 Finding/fingerprint
      → fingerprint 또는 CWE+file+line 중복 제거
  → service.orchestrator.Orchestrator.run (`run`만)
      → AnalysisProvider.analyze
      → PatchProvider.generate
      → VerificationProvider.verify
          → build
          → regression test
          → security re-scan
          → exploit mitigation
      → 실패 evidence를 PatchFeedback으로 다음 시도에 전달
      → 필수 게이트를 통과한 후보를 점수/변경 크기/ID 순으로 선택
      → `--apply`인 경우에만 SafePatchApplier.apply
  → repo.artifacts.ArtifactStore에 전체 evidence 기록
```

### `publish` 흐름

`publish`는 새 scan을 수행하지 않고 저장된 `VERIFIED` run을 읽습니다.

```text
CLI `publish TARGET RUN_ID`
  → ArtifactStore.read_run
  → service.publishing.PublishingService.publish
      → VERIFIED 및 eligible evidence 확인
      → autonomy 게이트와 clean worktree 확인
      → branch 생성
      → 원본 SHA를 확인하며 선택 패치 적용
      → 선택 옵션에 따라 commit → push → draft PR
  → 변경된 RunReport와 PR evidence 저장
```

API는 MVP에서 원본 적용을 의도적으로 거부합니다. `apply`와 publish는 로컬 CLI의 명시적 옵션과
설정 게이트를 함께 통과해야 합니다.

## 5. 기능별 코드 매핑

아래의 `src`, `config`, `rules`, `tests`, `scripts` 경로는 모두 `attack2patch/`를 기준으로
표기합니다. 루트 `scripts/`는 제품 구현이 아니라 저장소 전체 개발 하네스입니다.

| 기능 | 모델·인터페이스 | 정책·흐름 (`service`) | 실제 구현 (`runtime`/`ui`) | 설정·evidence | 대표 테스트 |
| --- | --- | --- | --- | --- | --- |
| 로컬 대상/허가 범위 | `HarnessSettings`, `ScopeSettings` | — | `ui/common.py`의 `validate_target`, `validate_dast_target` | `config/harness.yaml`의 `scope`, `dast` | `test_api.py`, `test_config.py` |
| 설정과 자율성 게이트 | `AutonomySettings`, provider별 settings | `publishing.py`의 publish 게이트 | `config/settings.py`의 YAML/env 파싱 | `config/harness.yaml`, `config/policies/` | `test_config.py`, `test_publishing.py` |
| 내장 Python 탐지 | `Scanner`, `Finding`, `Evidence` | `detection.py` | `builtin_scanner.py` | `detection.scanners` | `test_scanner.py` |
| Semgrep 탐지 | `Scanner`, `Finding` | `detection.py` | `semgrep_scanner.py` | `rules/semgrep/`, `config/tools.yaml` | scanner 계약은 orchestrator/demo 검증에 포함 |
| SARIF/Trivy/Gitleaks 정규화 | `Scanner`, `Finding` | `detection.py` | `external_scanners.py` | scanner별 timeout/required 설정 | `test_external_scanners.py` |
| fingerprint와 중복 제거 | `Finding.fingerprint` | `normalization.py`, `detection.py` | 각 scanner가 정규화 함수를 사용 | `findings.json` | `test_normalization.py`, `test_scanner.py` |
| root-cause 분석 | `AnalysisProvider`, `AnalysisResult` | `analysis.py` | 규칙 기반 분석은 `service/analysis.py`, 선택적 LLM은 `runtime/cli_llm_provider.py` | `finding-*/analysis.json` | `test_cli_llm_provider.py`, orchestrator 테스트 |
| 최소 패치 후보 | `PatchProvider`, `PatchCandidate`, `TextEdit` | `providers.py`가 여러 provider 결과 병합 | `builtin_patcher.py`, `cli_llm_provider.py` | `patching`, `llm`, `candidates.json` | `test_patcher.py`, `test_cli_llm_provider.py` |
| 안전한 패치 적용 | `PatchApplier`, `TextEdit.original_sha256` | orchestrator/publishing이 적용 시점 결정 | `patch_apply.py`, `fs.py` | `selected.diff`, 원본 SHA | `test_patcher.py`, `test_orchestrator.py` |
| build 검증 | `VerificationProvider`, `StageResult` | `scoring.py`, `orchestrator.py` | `verifier.py::_build`, `command.py` | `verification.build_*`, `evaluations.json` | `test_verifier.py` |
| regression 검증 | `StageResult` | 필수 게이트와 점수 반영 | `verifier.py::_functional_test` | opt-in test 설정, `evaluations.json` | `test_verifier.py`, `test_api.py` |
| security re-scan | `Finding`, `StageResult` | 잔존 finding이면 후보 탈락 | `verifier.py::_security_rescan` | scanner evidence, `evaluations.json` | `test_verifier.py` |
| exploit mitigation | `StageResult` | 가능한 검증 실패 시 후보 탈락 | `verifier.py::_exploit_mitigation`, `_manifest_security_tests` | `autopatch-security-tests.yaml` | `test_verifier.py`, 예제 `security_test.py` |
| 후보 점수·선택 | `PatchScore`, `CandidateEvaluation` | `scoring.py`, `orchestrator.py` | — | `evaluations.json`, `selected.diff` | `test_orchestrator.py`, `test_verifier.py` |
| 실패 피드백·재시도 | `PatchFeedback` | `orchestrator.py::_feedback_for_attempt` | patch provider가 feedback을 입력으로 받음 | `autonomy.max_patch_attempts`, `feedback.json` | `test_feedback.py` |
| run 평가 지표 | `RunMetrics` | `metrics.py` | — | `run.json` | orchestrator 테스트 |
| evidence/redaction | `RunReport`와 하위 모델 | 각 service가 기록 시점을 결정 | `repo/artifacts.py` | `.autopatch/runs/`, `logging.redact_patterns` | `test_artifacts.py` |
| Git branch/commit/push | `GitPublisher`, `PublishingResult` | `publishing.py` | `git_publisher.py` | `publishing`, `autonomy` | `test_publishing.py` |
| GitHub App draft PR | `PullRequestPublisher`, PR 모델 | `publishing.py`가 evidence 본문 생성 | `github_publisher.py` | `publishing.github_app` | `test_github_publisher.py` |
| CLI | 위 모델을 문자열/JSON으로 표시 | orchestrator/publishing 호출 | `ui/cli.py`, `__main__.py` | `AUTOPATCH_CONFIG` | 핵심 동작은 service/API 테스트로 검증 |
| FastAPI | 요청 모델과 `RunReport` | orchestrator 호출, 동시 run 잠금 | `ui/api.py` | API에서는 apply 금지 | `test_api.py` |
| staging/canary/rollback | `DeploymentProvider`, `DeploymentResult` | 현재 기본 run/publish 루프와 분리 | `deployment.py` | `deployment.*`, rollback runbook | 설정 검증과 향후 provider 통합 대상 |
| JSON Schema/문서 검증 | Pydantic 모델 | — | `scripts/generate-schemas.py`, check scripts | `schemas/`, 상위 `docs/generated/` | `scripts/check.sh` |

## 6. 기능을 변경할 때의 탐색 경로

### Scanner를 추가할 때

1. `providers/contracts.py`의 `Scanner` 계약을 확인합니다.
2. `runtime/`에 adapter와 외부 출력 parser를 구현합니다.
3. 모든 출력 경로를 `Finding`으로 파싱하고 결정적 fingerprint를 만듭니다.
4. `runtime/factory.py`에 설정 기반 조립을 추가합니다.
5. `config/harness.yaml`과 `config/tools.yaml`에 timeout/required 정책을 추가합니다.
6. 정상 결과, 결과 없음, 도구 미설치, 실행 실패를 각각 테스트합니다.

### 취약점 패처를 추가할 때

1. `types/models.py`의 `AnalysisResult`, `PatchCandidate`, `TextEdit`를 읽습니다.
2. `providers/contracts.py`의 `PatchProvider.generate`를 구현합니다.
3. 원본 파일 전체가 아닌 최소 `TextEdit`와 unified diff를 생성합니다.
4. `service/providers.py` 또는 `runtime/factory.py`에 provider를 등록합니다.
5. 해당 CWE의 re-scan과 exploit mitigation이 `verifier.py`에서 독립적으로 판정되는지 확인합니다.
6. 오래된 SHA, scanner 우회, 변경 라인 제한 테스트를 추가합니다.

### 검증 단계를 추가하거나 바꿀 때

1. `StageResult`와 `VerificationReport` 데이터 계약을 먼저 변경합니다.
2. `runtime/verifier.py`에서 임시 복사본에 대한 실제 검증을 구현합니다.
3. `service/scoring.py`와 `eligible` 필수 게이트의 영향을 확인합니다.
4. `orchestrator.py`의 실패 상태와 `PatchFeedback` 변환을 갱신합니다.
5. schema를 재생성하고 PASS/FAIL/SKIPPED/ERROR를 모두 테스트합니다.

### Git/PR provider를 추가할 때

1. `GitPublisher` 또는 `PullRequestPublisher` Protocol을 구현합니다.
2. `service/publishing.py`의 VERIFIED-only 정책은 provider 밖에 유지합니다.
3. `runtime/factory.py::build_publishing_service`에서 구현을 선택합니다.
4. 자격 증명은 환경 변수 이름만 설정에 저장하고 evidence에는 값을 남기지 않습니다.
5. 실제 원격 대신 mock HTTP/로컬 임시 Git 저장소로 계약을 테스트합니다.

### 데이터 모델을 바꿀 때

1. `types/models.py`를 수정합니다.
2. 해당 모델의 producer와 consumer를 모두 찾습니다.
3. `attack2patch/`에서 `python scripts/generate-schemas.py`를 실행해 `schemas/`를 갱신하고,
   필요한 경우 상위 `docs/generated/`의 사람이 읽는 참조도 함께 갱신합니다.
4. 기존 run artifact를 읽는 호환성 영향과 API 응답 변화를 확인합니다.

## 7. 테스트에서 기능 찾기

`attack2patch/tests/`는 구현 디렉터리를 그대로 복제하지 않고 사용자 관찰 동작별로 구성되어
있습니다.

| 테스트 | 보장하는 핵심 동작 |
| --- | --- |
| `test_scanner.py` | 내장 CWE-89 탐지와 fingerprint 결정성 |
| `test_external_scanners.py` | SARIF, Trivy, Gitleaks의 공통 Finding 변환 |
| `test_normalization.py` | 상대 경로 안전성과 cross-scanner 상관관계 |
| `test_patcher.py` | 최소 parameterized-query diff와 stale hash 차단 |
| `test_verifier.py` | build/regression/re-scan/exploit 및 fail-closed 동작 |
| `test_feedback.py` | 검증 실패가 제한된 다음 후보 생성에 전달됨 |
| `test_orchestrator.py` | dry-run 보존과 VERIFIED-only apply |
| `test_artifacts.py` | evidence 기록 시 secret redaction |
| `test_cli_llm_provider.py` | 세 CLI argv 격리, 구조화 출력 parsing, TextEdit 검증 |
| `test_publishing.py` | 검증된 파일만 branch/commit하는 로컬 Git 흐름 |
| `test_github_publisher.py` | GitHub App token 교환과 draft PR 요청 |
| `test_api.py` | API 입력 경계, apply 금지, run 조회 |
| `test_config.py` | 잘못된 정책 조합과 미허가 DAST 차단 |

루트 전체 검증 진입점은 `bash scripts/check.sh`이며 내부에서 제품 검증도 호출합니다. 제품만
검증하려면 `cd attack2patch && bash scripts/check.sh`를 사용합니다. 예제 CWE-89의 탐지부터
실제 복사본 적용까지 따라가려면 제품 디렉터리에서 `bash scripts/demo.sh`를 실행하고 생성된
`.autopatch/runs/<run-id>/`를 코드와 함께 비교합니다.

## 8. 현재 구현 경계

코드를 읽을 때 다음을 구현 완료로 오해하지 않도록 주의합니다.

- 내장 자동 패처의 결정적 수정 범위는 현재 **CWE-89**입니다.
- Codex CLI 분석·패치 provider가 기본 활성화되며 OpenCode/Claude는 설정이나 `--llm-cli`로 교체합니다.
- 선택한 CLI의 설치와 자체 로그인이 필요하며 Attack2Patch는 API key를 보관하지 않습니다.
- Semgrep, Trivy, Gitleaks는 설치된 경우 실행되는 선택 provider입니다.
- DAST는 허가 설정과 경계 검증이 있으며 ZAP/Nuclei 실행 adapter는 향후 범위입니다.
- staging/canary/rollback은 명령 provider와 runbook이 있지만 기본 오케스트레이션에서 자동
  실행하지 않습니다.
- FastAPI는 조회와 dry-run 실행 경계이며 원본 apply와 publish를 허용하지 않습니다.
- 인증/인가, IDOR, 복잡한 비즈니스 로직은 자동 수정보다 사람 검토가 우선입니다.

구현/스캐폴드/계획 상태의 전체 구분은
[`docs/IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md)에서 확인합니다.
