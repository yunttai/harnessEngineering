# Attack2Patch

취약점 **탐지 → 원인 분석 → 최소 패치 후보 생성 → 빌드·회귀·보안 검증 → Git/PR 전달**을
하나의 검증 중심 루프로 구성한 에이전트 우선 보안 하네스입니다.

이 저장소는 다음 네 축으로 구성됩니다.

1. **짧은 맵**: `AGENTS.md`, `ARCHITECTURE.md`
2. **지식베이스**: `docs/`
3. **역할 에이전트**: `.opencode/agent/`
4. **기계적 검증**: `scripts/`, `tests/`, GitHub Actions

현재 구현은 **로컬·허가된 소스 저장소를 대상으로 한 MVP**입니다. 기본 동작은 dry-run이며,
원본 코드 수정, 브랜치 생성, PR 생성, 배포는 명시적으로 허용해야 합니다.

`autopatch` Python package와 기존 `autopatch` console alias는 호환성을 위해 유지하며, 제품명과
기본 CLI 명령은 `Attack2Patch`/`attack2patch`입니다.

## 빠른 시작

요구 환경:

- Python 3.11 이상
- Git
- 선택: Semgrep, Trivy, Gitleaks, Docker, GitHub CLI

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

bash scripts/check.sh
attack2patch scan examples/vulnerable_flask
attack2patch run examples/vulnerable_flask
```

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

python -m autopatch.ui.cli scan examples\vulnerable_flask
python -m autopatch.ui.cli run examples\vulnerable_flask
```

검증된 후보를 예제 복사본에 실제 반영하려면:

```bash
bash scripts/demo.sh
```

원본 대상에 직접 반영할 때만 `--apply`를 사용합니다.

```bash
attack2patch run /path/to/authorized/repository --apply --execute-tests --execute-security-tests
```

`--execute-tests`는 대상 저장소의 일반 테스트를, `--execute-security-tests`는 대상 루트의
`autopatch-security-tests.yaml`에 선언된 보안 재현 명령을 실행합니다. 두 옵션 모두 대상 코드를
실행하므로 신뢰할 수 없는 저장소에서는 로컬 실행하지 말고 격리된 컨테이너/VM 실행기를
연결해야 합니다.

## 에이전트 실행

OpenCode에서 `orchestrator`를 1차 에이전트로 선택합니다.

```bash
opencode --agent orchestrator
```

예시 프롬프트:

```text
docs/product-specs/PRD.md와 docs/exec-plans/active/mvp1.md를 읽고,
examples/vulnerable_flask를 대상으로 탐지부터 검증까지 실행해.
원본 파일은 수정하지 말고 evidence와 patch candidate를 먼저 제시해.
```

오케스트레이터의 기본 루프:

```text
detector
   ↓
analyzer
   ↓
patcher ───────────────┐
   ↓                   │
verifier               │
   ├─ FAIL → feedback ─┘
   └─ PASS
        ↓
reviewer + security
        ↓
committer
        ↓
deployer (명시적 승인 시)
```

## CLI

```bash
attack2patch scan TARGET
attack2patch run TARGET
attack2patch run TARGET --apply
attack2patch run TARGET --execute-tests
attack2patch run TARGET --execute-security-tests
attack2patch publish TARGET RUN_ID --commit
attack2patch validate-config
attack2patch serve --host 127.0.0.1 --port 8000
```

`publish`는 VERIFIED run만 받으며 `apply_patch`, `create_branch`, `create_commit`,
`push_branch`, `create_pull_request` 정책을 각각 검사합니다. 원격 push와 draft PR에는 해당 CLI
옵션과 설정 게이트가 모두 필요합니다.

## 선택 공급자

- OpenAI Responses structured output: `config/harness.yaml`의 `llm.enabled`를 켜고
  `OPENAI_API_KEY`를 설정합니다. API 출력은 strict JSON Schema 뒤 다시 Pydantic으로 파싱되며,
  후보는 원본 hash·경로·TextEdit 범위를 로컬에서 재검증합니다.
- GitHub App PR: `publishing.github_app`의 repository를 지정하고 App ID, installation ID,
  private key 환경 변수를 설정합니다. 기본값은 비활성이며 contents/pull-requests 최소 권한을
  사용합니다.
- Trivy/Gitleaks/Semgrep: 설치된 optional scanner만 실행하며 미설치는 SKIPPED evidence로
  남깁니다. CodeQL을 포함한 SARIF 결과는 공통 parser로 정규화할 수 있습니다.

주요 산출물은 대상 저장소가 아니라 하네스 실행 위치의 `.autopatch/runs/<run-id>/`에 기록됩니다.

```text
run.json
findings.json
finding-<id>/
├── analysis.json
├── candidates.json
├── evaluations.json
└── selected.diff
```

## 레포지토리 구조

```text
AGENTS.md
ARCHITECTURE.md
.opencode/agent/              역할별 에이전트 프롬프트
config/                       하네스·도구·자율성 정책
docs/                         지식베이스와 실행 계획
rules/                        로컬 탐지·시큐어코딩 규칙
schemas/                      기계 판독 가능한 데이터 스키마
scripts/                      검증·데모·문서 정리
src/autopatch/
├── types/                    Finding, Patch, Verification 스키마
├── config/                   설정 파싱
├── providers/                교차 관심사 인터페이스
├── repo/                     실행 증거 저장소
├── service/                  순수 파이프라인 로직
├── runtime/                  scanner, sandbox, git 어댑터
└── ui/                       CLI, FastAPI
tests/                        하네스 자체 검증
examples/vulnerable_flask/    재현 가능한 CWE-89 데모
```

## 안전 기본값

- 로컬 파일 경로만 입력으로 받습니다.
- dry-run이 기본값입니다.
- 패치는 전체 파일 재생성보다 구조화된 최소 `TextEdit`와 unified diff로 관리합니다.
- 빌드·테스트·재스캔 결과가 없으면 패치 성공으로 판정하지 않습니다.
- 테스트 실행, Git 변경, PR, 배포는 각각 별도 허용 항목입니다.
- DAST/공격 재현은 `authorized_targets`에 포함된 환경에서만 수행하도록 정책을 분리했습니다.
- 실패 결과도 evidence로 보존하여 다음 패치 시도에 전달합니다.

## 개발 검증

```bash
bash scripts/check.sh
bash scripts/doc-gardening.sh
pytest -q
```

## MVP 범위

구현됨:

- Python AST 기반 CWE-89/78/502 및 단순 하드코딩 시크릿 탐지
- Semgrep JSON 어댑터
- Trivy/Gitleaks JSON 및 SARIF 공통 parser
- 공통 Finding Schema와 중복 제거
- 결정적 root-cause 분석
- 제한된 CWE-89 최소 패치 후보 생성
- 임시 복사본에서 build/test/re-scan/manifest 및 구조적 exploit mitigation 검증
- 계획서의 40/30/15/10/5 패치 점수 모델
- 실행 evidence 저장
- bounded verification feedback 재패치와 집계 평가 지표
- OpenAI Responses strict structured-output 분석/패치 공급자
- verified-only local Git publish 및 GitHub App draft PR 공급자
- staging/canary/rollback argv 공급자와 rollback runbook
- FastAPI/CLI 진입점
- OpenCode 역할 에이전트와 문서 하네스
- CI 검증

남은 확장 지점:

- Docker/Firecracker 격리 실행기
- ZAP/Nuclei differential DAST 실행기
- 실제 환경별 staging/canary 관측 adapter
- 인증·인가·비즈니스 로직 취약점용 상태/의존 그래프

구현 범위와 아직 스캐폴드/계획 상태인 항목은 `docs/IMPLEMENTATION_STATUS.md`에서
원본 계획 항목별로 확인할 수 있습니다.

## 중요 제한

이 MVP의 내장 패처는 의도적으로 지원 범위를 좁혔습니다. 알 수 없는 프레임워크, 다중 쿼리,
복잡한 ORM, 인증/인가, 비즈니스 로직은 자동 수정하지 않고 `NEEDS_HUMAN_REVIEW`로 남깁니다.
탐지 결과가 사라졌다는 사실만으로 수정 완료로 판정하지 않으며, 검증 가능한 evidence가
부족하면 제한된 신뢰도로 표시합니다.
