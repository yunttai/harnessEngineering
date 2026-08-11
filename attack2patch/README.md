# Attack2Patch

로컬·허가된 소스 저장소를 대상으로 취약점 **탐지 → 정규화 → 원인 분석 → 최소 패치 후보
생성 → build·회귀·보안 검증 → Git/PR 전달**을 수행하는 실행 제품입니다.

이 디렉터리는 상위 `harnessEngineering` 저장소의 개발 에이전트와 문서 하네스에 의존하지 않는
독립 Python 프로젝트입니다. 이 디렉터리만 별도로 복사한 뒤에도 설치, CLI/API 실행, 테스트와
CWE-89 데모를 수행할 수 있습니다.

## 구조

```text
attack2patch/
├── pyproject.toml               패키지와 CLI entry point
├── config/                      scope, autonomy, scanner, provider 설정
├── rules/                       Semgrep 규칙
├── schemas/                     Finding/RunReport JSON Schema
├── src/autopatch/               제품 소스 코드
├── tests/                       제품 테스트
├── examples/vulnerable_flask/   CWE-89 실행 예제
├── scripts/                     제품 자체 검사·스키마 생성·데모
├── Dockerfile
├── docker-compose.yml
└── Makefile
```

## 설치

Python 3.11 이상이 필요합니다.

Linux/macOS:

```bash
cd attack2patch
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Windows PowerShell:

```powershell
Set-Location attack2patch
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## 실행

```bash
attack2patch validate-config
attack2patch scan examples/vulnerable_flask
attack2patch run examples/vulnerable_flask
attack2patch serve --host 127.0.0.1 --port 8000
```

Windows에서 editable install 없이 소스를 직접 실행할 수도 있습니다.

```powershell
python scripts\run-cli.py scan examples\vulnerable_flask
python scripts\run-cli.py run examples\vulnerable_flask
```

기본 설정은 `config/harness.yaml`이며 다른 위치를 사용할 때는 CLI의 `--config` 또는
`AUTOPATCH_CONFIG` 환경 변수를 지정합니다.

```bash
AUTOPATCH_CONFIG=/absolute/path/harness.yaml attack2patch scan /authorized/repository
```

## 안전 기본값

- 로컬 경로만 입력으로 받습니다.
- 원본 변경 없이 후보와 evidence를 만드는 dry-run이 기본입니다.
- 대상 저장소 테스트와 보안 재현 명령 실행은 각각 opt-in입니다.
- 원본 SHA-256이 후보 생성 시점과 다르면 패치 적용을 중단합니다.
- build, regression, security re-scan, exploit 필수 게이트를 통과하지 못한 후보는 선택하지
  않습니다.
- apply, branch, commit, push, PR, deploy 권한은 독립된 설정 게이트입니다.
- DAST는 명시적으로 허가된 target만 받을 수 있습니다.
- evidence 저장 전 구성된 패턴과 고신뢰 secret 형식을 redaction합니다.

대상 원본에 검증된 후보를 적용하려는 경우에만 `--apply`를 사용합니다.

```bash
attack2patch run /authorized/repository \
  --apply \
  --execute-tests \
  --execute-security-tests
```

`--execute-security-tests`는 대상 루트의 `autopatch-security-tests.yaml`에 선언된 argv 명령을
실행합니다. 신뢰할 수 없는 저장소는 로컬에서 실행하지 말고 격리 provider를 연결해야 합니다.

## 검증된 패치 게시

```bash
attack2patch publish /authorized/repository RUN_ID --commit
attack2patch publish /authorized/repository RUN_ID --commit --push
attack2patch publish /authorized/repository RUN_ID --commit --push --pull-request
```

`publish`는 저장된 상태가 `VERIFIED`이고 선택 후보에 eligible verification evidence가 있는
run만 처리합니다. 명령 옵션뿐 아니라 `config/harness.yaml`의 autonomy 게이트도 켜져 있어야
합니다. GitHub App draft PR을 사용하려면 `publishing.github_app` 설정과 자격 증명 환경 변수가
필요합니다.

## Evidence

실행 결과는 현재 작업 디렉터리의 `.autopatch/runs/<run-id>/`에 저장됩니다.

```text
run.json
findings.json
finding-<id>/
├── analysis.json
├── candidates.json
├── evaluations.json
├── feedback.json
└── selected.diff
```

## 자체 검증

제품 디렉터리 안에서 다음 명령을 실행합니다.

```bash
bash scripts/check.sh
bash scripts/demo.sh
```

`check.sh`는 레이어 의존성, 설정, 생성 스키마, secret, compile, 전체 테스트를 검사합니다.
`demo.sh`는 취약한 Flask 예제를 임시 복사해 탐지·분석·패치·검증·적용한 뒤 post-patch scan이
0건인지 확인합니다.

## 선택 provider와 현재 경계

- 내장 Python scanner: CWE-89, CWE-78, CWE-502와 단순 하드코딩 secret 탐지
- 내장 patcher: 제한된 CWE-89 parameterized query 수정
- 선택 scanner: Semgrep, Trivy, Gitleaks 및 SARIF parser
- 선택 LLM: 로컬 Codex, OpenCode, Claude CLI의 구조화 출력
- 게시: 로컬 Git과 GitHub App draft PR
- 배포: staging/canary/rollback argv provider와 명시적 설정 게이트

LLM CLI는 기본 비활성이며, 선택한 CLI를 먼저 설치하고 해당 CLI 자체 로그인 절차를 완료해야
합니다. Attack2Patch는 API key를 직접 받거나 저장하지 않습니다. 한 번의 run에서만 활성화하려면:

```bash
attack2patch run examples/vulnerable_flask --llm-cli codex
attack2patch run examples/vulnerable_flask --llm-cli opencode --llm-model provider/model
attack2patch run examples/vulnerable_flask --llm-cli claude --llm-model sonnet
```

상시 설정은 `config/harness.yaml`의 `llm.enabled`, `llm.provider`, `llm.model`을 사용합니다.
CLI는 대상 저장소가 아닌 빈 임시 디렉터리에서 실행되며, Codex와 Claude는 native JSON Schema,
OpenCode는 JSON event stream을 사용합니다. 세 경로 모두 출력이 로컬 Pydantic 스키마와 파일
경로·라인 범위·원본 hash 검증을 다시 통과해야 후보가 됩니다. 외부 scanner와 GitHub App도
기본 비활성이며, 설치 또는 자격 증명이 없으면 자동 성공으로 간주하지 않습니다. 인증/인가,
IDOR, 복잡한 비즈니스 로직은 자동 수정 범위가 아닙니다.
