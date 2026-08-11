# Attack2Patch Engineering Repository

이 저장소는 **실제로 설치·실행하는 Attack2Patch 제품**과 그 제품을 설계·개발·검증하는
**엔지니어링 하네스**를 물리적으로 분리한 모노레포입니다.

```text
harnessEngineering/
├── attack2patch/       독립 실행 가능한 제품 패키지
├── docs/               PRD, 설계 결정, 코드 리딩, 실행 계획
├── .opencode/agent/    개발 역할별 에이전트 프롬프트
├── scripts/            저장소 맵·문서·전체 품질 검증
├── AGENTS.md           작업 규약과 저장소 지도
└── ARCHITECTURE.md     제품 파이프라인과 레이어 불변 조건
```

제품을 설치하거나 실행하려면 [attack2patch/README.md](attack2patch/README.md)에서 시작합니다.
상위 개발 하네스 없이 `attack2patch/` 디렉터리만 별도로 복사해도 설치, 테스트, CLI/API와
CWE-89 데모가 동작하도록 구성되어 있습니다.

## 제품 빠른 실행

```bash
cd attack2patch
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"

bash scripts/check.sh
attack2patch scan examples/vulnerable_flask
attack2patch run examples/vulnerable_flask
bash scripts/demo.sh
```

Windows PowerShell:

```powershell
Set-Location attack2patch
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"

python -m autopatch.ui.cli scan examples\vulnerable_flask
python -m autopatch.ui.cli run examples\vulnerable_flask
```

`run`은 기본적으로 로그인된 로컬 Codex CLI를 사용합니다. OpenCode 또는 Claude로 바꾸려면
`--llm-cli opencode` 또는 `--llm-cli claude`를 지정합니다. LLM 없는 결정적 실행은
`--no-llm`을 명시해야 하며 API key는 Attack2Patch 설정에 저장하지 않습니다.

## 개발 하네스

루트 문서는 요구사항, 설계 근거, 자율성 정책, 구현 상태와 변경 계획의 단일 기록
시스템입니다. 권장 읽기 순서는 다음과 같습니다.

1. [AGENTS.md](AGENTS.md)
2. [ARCHITECTURE.md](ARCHITECTURE.md)
3. [코드 리딩 가이드](docs/CODE_READING_GUIDE.md)
4. [PRD](docs/product-specs/PRD.md)
5. [구현 상태](docs/IMPLEMENTATION_STATUS.md)

전체 저장소를 검증하려면 루트에서 실행합니다.

```bash
bash scripts/check.sh
bash scripts/doc-gardening.sh
```

루트 `scripts/check.sh`는 저장소 맵·문서 링크·전체 secret을 먼저 검사한 뒤
`attack2patch/scripts/check.sh`를 호출하여 제품의 아키텍처, 설정, 스키마, compile과 테스트를
검증합니다.

MVP 3의 Docker 격리와 DAST는 기본 비활성입니다. 설정의 sandbox/DAST autonomy와 CLI의
`--sandbox docker --execute-dast`를 함께 지정해야 하며, 배포도 `deploy --approve`와 독립
정책 게이트를 모두 요구합니다.

운영 하드닝은 multi-architecture manifest digest로 고정한 Docker 이미지를 amd64/arm64
GitHub Actions matrix에서 검증합니다. 결정적 Python 패처는 CWE-89 외에도 안전한 AST shape가
확정되는 좁은 CWE-22, CWE-78, CWE-502 패턴을 지원합니다.

## 변경 위치 선택

| 변경 목적 | 작업 위치 |
| --- | --- |
| scanner, patcher, verifier, CLI/API 구현 | `attack2patch/src/autopatch/` |
| 제품 설정, 규칙, JSON Schema | `attack2patch/config/`, `attack2patch/rules/`, `attack2patch/schemas/` |
| 제품 회귀 테스트와 실행 예제 | `attack2patch/tests/`, `attack2patch/examples/` |
| PRD, 설계 결정, 보안·신뢰성 원칙 | `docs/` |
| 개발 에이전트 역할과 협업 규약 | `.opencode/agent/`, `docs/AGENT_TEAM.md` |
| 저장소 전체 구조·문서 품질 검사 | 루트 `scripts/` |

제품 디렉터리와 개발 하네스의 세부 매핑은
[docs/CODE_READING_GUIDE.md](docs/CODE_READING_GUIDE.md)를 참고합니다.
