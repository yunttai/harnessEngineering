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
python -m pip install --constraint constraints.txt -e ".[dev]"
```

Windows PowerShell:

```powershell
Set-Location attack2patch
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --constraint constraints.txt -e ".[dev]"
```

## 실행

기본 `run`은 로컬에 설치되고 로그인된 **Codex CLI**를 패치 후보 provider로 사용합니다.
Codex를 먼저 준비한 뒤 실행합니다.

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
- `scan`과 `run`은 원본 변경 없이 후보와 evidence를 만드는 dry-run이 기본입니다.
- 대상 저장소 테스트와 보안 재현 명령 실행은 각각 opt-in입니다.
- 원본 SHA-256이 후보 생성 시점과 다르면 패치 적용을 중단합니다.
- 패치 `run`은 기본적으로 Codex CLI 후보와 내장 결정적 후보를 함께 생성·검증합니다.
- build, regression, security re-scan, exploit 필수 게이트를 통과하지 못한 후보는 선택하지
  않습니다.
- `publish`는 VERIFIED 패치를 기본 `Attack2patch` 브랜치에 적용·커밋·push하며,
  `--no-push`/`--no-commit`으로 줄일 수 있습니다. PR과 deploy는 계속 별도 승인입니다.
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
실행합니다. manifest는 strict JSON Schema로 검증되며 `baseline_expected_exit_code`와
`expected_exit_code`로 패치 전후 결과를 비교할 수 있습니다.

신뢰할 수 없는 저장소는 Docker provider를 명시합니다. Docker 모드는 원본 read-only mount,
writable 임시 workspace, read-only root filesystem, cap drop, CPU/memory/PID 제한과 기본
network none을 사용합니다. Docker 실패 시 local-copy로 자동 fallback하지 않습니다.
이미지 자동 pull도 기본 금지이므로 운영자가 검증한 image를 미리 준비하거나 별도 게이트를
켜야 합니다. 기본 Python/ZAP/Nuclei image는 amd64와 arm64를 포함하는 manifest digest로
고정되며 `scripts/check-production-policy.py`가 tag 회귀를 차단합니다.

```bash
attack2patch run /authorized/repository \
  --sandbox docker \
  --execute-tests \
  --execute-security-tests
```

동적 애플리케이션 DAST는 `dast.enabled`, `autonomy.execute_dast`,
`dast.allow_sandbox_loopback` 설정과 CLI 옵션을 모두 요구합니다. 이 설정은 host port를
publish하지 않으며, 하네스가 생성한 Docker internal network의 앱 target만 허가합니다.

```bash
attack2patch run /authorized/repository --sandbox docker --execute-dast
attack2patch dast https://authorized-staging.example --tool nuclei
```

## 검증된 패치 게시

```bash
attack2patch publish /authorized/repository RUN_ID
attack2patch publish /authorized/repository RUN_ID --no-push
attack2patch publish /authorized/repository RUN_ID --pull-request
```

`publish`는 저장된 상태가 `VERIFIED`이고 선택 후보에 eligible verification evidence가 있는
run만 처리합니다. 기본 설정은 `Attack2patch` 브랜치를 만들고 선택 파일만 commit한 뒤
`origin`으로 push합니다. 같은 이름의 로컬 브랜치가 이미 있으면 덮어쓰지 않고 실패하며,
다른 이름은 `--branch NAME`으로 지정합니다. GitHub App draft PR을 사용하려면
`--pull-request`, `publishing.github_app` 설정과 자격 증명 환경 변수가
필요합니다. PR을 만들기 전에 App 설치 ID, exact repository 접근과 최소 권한을 읽기 검증할
수 있습니다. 이 명령은 installation token을 발급하지만 repository 상태는 변경하지 않습니다.

```bash
attack2patch github-app-smoke --repository OWNER/REPOSITORY --json
```

pushed commit/branch/remote evidence가 생성된 run은 PR 없이도 별도의 배포 승인으로 staging,
canary, bounded observation과 production promotion을 실행할 수 있습니다. 어느 단계든 실패하거나
관측 시도 한도를 소진하면 rollback command가 실행되며 결과가 동일 RunReport에 보존됩니다.
실제 환경 명령은 `runbooks/rollback.md` 계약을 따라야 합니다.

```bash
attack2patch deploy /authorized/repository RUN_ID --approve
```

호스트에 Semgrep/Trivy가 없어도 digest 고정 공식 컨테이너로 네 scanner를 모두 필수 실행하고,
Docker 격리 검증과 DAST까지 수행하는 운영 프로필은 다음처럼 명시적으로 선택합니다.

```bash
attack2patch run /authorized/repository --config config/production.yaml \
  --execute-tests --execute-security-tests --execute-dast
```

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

- 내장 Python scanner: CWE-22/78/89/502와 단순 하드코딩 secret 탐지
- 내장 patcher: 제한된 CWE-89 parameterized query, CWE-78 shell f-string→argv,
  CWE-502 unsafe YAML→safe_load, CWE-22 Flask safe directory API
- 선택 scanner: Semgrep, Trivy, Gitleaks 및 SARIF parser
- 기본 LLM: 로컬 Codex CLI의 구조화 출력
- 대체 LLM: OpenCode 또는 Claude CLI
- 게시: 로컬 Git, GitHub App read-only credential smoke와 draft PR
- 격리: Docker read-only source/rootfs, writable workspace, resource/network 제한
- DAST: ZAP/Nuclei authorized provider와 baseline/patched differential oracle
- 배포: pushed-commit-only staging/canary/bounded observation/promotion/rollback과 명시적 CLI 승인

LLM CLI는 기본 활성화되어 있으며 기본 provider는 `codex`입니다. 선택한 CLI를 먼저 설치하고
해당 CLI 자체 로그인 절차를 완료해야 합니다. Attack2Patch는 API key를 직접 받거나 저장하지
않습니다. 다른 CLI를 선택하려면:

```bash
attack2patch run examples/vulnerable_flask --llm-cli opencode --llm-model provider/model
attack2patch run examples/vulnerable_flask --llm-cli claude --llm-model sonnet
```

LLM을 의도적으로 사용하지 않는 결정적 fallback 실행만 `--no-llm`으로 요청합니다.

```bash
attack2patch run examples/vulnerable_flask --no-llm
```

상시 설정은 `config/harness.yaml`의 `llm.enabled`, `llm.provider`, `llm.model`을 사용합니다.
CLI는 대상 저장소가 아닌 빈 임시 디렉터리에서 실행되며, Codex와 Claude는 native JSON Schema,
OpenCode는 JSON event stream을 사용합니다. 세 경로 모두 출력이 로컬 Pydantic 스키마와 파일
경로·라인 범위·원본 hash 검증을 다시 통과해야 후보가 됩니다. 외부 scanner와 GitHub App도
기본 비활성이며, 설치 또는 자격 증명이 없으면 자동 성공으로 간주하지 않습니다. 인증/인가,
IDOR, 복잡한 비즈니스 로직은 자동 수정 범위가 아닙니다.
