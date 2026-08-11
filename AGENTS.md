# AGENTS.md

이 파일은 저장소의 **목차와 실행 지도**입니다. 세부 규칙과 근거는 `docs/`가 단일 기록
시스템(system of record)으로 제공합니다. 작업을 시작할 때 이 파일과 `ARCHITECTURE.md`를
먼저 읽습니다.

## 목표

로컬·허가된 저장소에서 다음 폐쇄형 루프를 수행합니다.

```text
Detection → Normalization → Analysis → Patch Candidates
→ Build/Test/Re-scan/Exploit Verification → Review → PR/Deploy
```

LLM 또는 에이전트의 설명이 아니라 실제 실행 evidence가 최종 판정을 담당합니다.

## 읽는 순서

1. `ARCHITECTURE.md`
2. `docs/index.md`
3. `docs/product-specs/PRD.md`
4. 현재 실행 계획 `docs/exec-plans/active/`
5. 작업에 해당하는 Agent와 설계 문서

## 저장소 맵

```text
AGENTS.md
ARCHITECTURE.md
README.md
.opencode/agent/
config/
docs/
├── index.md
├── AGENT_TEAM.md
├── DESIGN.md
├── SECURITY.md
├── RELIABILITY.md
├── PLANS.md
├── QUALITY_SCORE.md
├── product-specs/
├── design-docs/
├── exec-plans/
├── generated/
└── references/
rules/
schemas/
scripts/
src/autopatch/
├── types/
├── config/
├── providers/
├── repo/
├── service/
├── runtime/
└── ui/
tests/
examples/
```

## 작업 규약

- **허가 범위**: 사용자가 소유하거나 명시적으로 허가받은 로컬 저장소만 처리합니다.
- **기본 dry-run**: 원본 수정, Git 작업, PR, 배포는 각각 명시적으로 허용해야 합니다.
- **경계 파싱**: Scanner/LLM/프로세스 출력은 Pydantic 스키마로 파싱한 뒤 사용합니다.
- **최소 패치**: 전체 파일 재생성보다 위치가 고정된 `TextEdit`와 unified diff를 사용합니다.
- **검증 우선**: build, regression, re-scan, exploit mitigation 중 실패한 항목이 있으면
  패치를 VERIFIED로 표시하지 않습니다.
- **독립 리뷰**: patcher가 자신의 패치를 최종 승인하지 않습니다.
- **Evidence 보존**: 성공과 실패를 모두 `.autopatch/runs/`에 기록합니다.
- **재시도 제한**: 동일 Finding에 대한 자동 재패치는 설정된 최대 횟수를 넘지 않습니다.
- **복잡 취약점**: 인증/인가·IDOR·비즈니스 로직은 자동 수정보다 사람 검토를 우선합니다.

## 코드 레이어 불변 조건

```text
Types → Config → Repo → Service → Runtime → UI
          Providers는 명시적 인터페이스로만 교차 관심사를 주입
```

낮은 레이어가 높은 레이어를 import하지 않습니다. 세부 규칙은 `ARCHITECTURE.md`에 있으며
`scripts/check-architecture.py`가 기계적으로 검사합니다.

## 검증

변경 후 반드시 실행합니다.

```bash
bash scripts/check.sh
```

## 상태 기록

- 활성 계획: `docs/exec-plans/active/`
- 완료 계획: `docs/exec-plans/completed/`
- 기술 부채: `docs/exec-plans/tech-debt-tracker.md`
- 품질 등급: `docs/QUALITY_SCORE.md`
