# 지식베이스 색인

`docs/`는 코드가 아닌 프로젝트 지식의 단일 기록 시스템입니다. 짧은 맵은 `AGENTS.md`,
최상위 코드·파이프라인 구조는 `ARCHITECTURE.md`가 담당합니다.

실행 제품은 [`../attack2patch/`](../attack2patch/README.md)에 독립 Python 프로젝트로 분리되어
있고, 이 디렉터리는 제품을 개발·검증하는 지식 하네스만 담당합니다.

## 신규 에이전트 읽기 순서

1. `../AGENTS.md`
2. `../ARCHITECTURE.md`
3. `CODE_READING_GUIDE.md`
4. `product-specs/PRD.md`
5. `AGENT_TEAM.md`
6. 현재 `exec-plans/active/`
7. 작업에 해당하는 설계·보안·운영 문서

## 문서 맵

| 경로 | 내용 |
| --- | --- |
| `AGENT_TEAM.md` | 역할별 에이전트와 협업·재시도 루프 |
| `DESIGN.md` | 패치 생성과 코드 변경의 골든 룰 |
| `SECURITY.md` | 허가 범위, sandbox, secret, 보안 검증 |
| `RELIABILITY.md` | timeout, 재현성, evidence, 실패 처리 |
| `PLANS.md` | 실행 계획 작성·완료 규약 |
| `PRODUCT_SENSE.md` | 제품 판단 원칙 |
| `QUALITY_SCORE.md` | 하네스 구성 요소의 품질 등급 |
| `TOOL_REGISTRY.md` | 도구 등록·정규화·실행 규약 |
| `DATA_MODEL.md` | Finding/Patch/Verification/Run 데이터 모델 |
| `IMPLEMENTATION_STATUS.md` | 원본 계획 대비 구현·스캐폴드·계획 상태 |
| `CODE_READING_GUIDE.md` | 디렉터리 구조, 실행 흐름, 기능별 구현·테스트 매핑 |
| `product-specs/` | PRD와 기능별 수용 기준 |
| `design-docs/` | 아키텍처 결정과 검증 상태 |
| `secure-coding/` | CWE별 수정 원칙 |
| `exec-plans/` | 활성·완료 계획과 기술 부채 |
| `generated/` | 코드에서 생성된 스키마 문서 |
| `references/` | 원본 계획서와 외부 레포 구조 요약 |

## 유지 규칙

- 새 문서는 이 색인에 등록합니다.
- 결정은 무엇뿐 아니라 왜를 남깁니다.
- 코드와 어긋난 문서는 드리프트로 간주합니다.
- 반복되는 규칙은 문서에만 두지 말고 스크립트·테스트·타입으로 승격합니다.
- `bash scripts/doc-gardening.sh`로 DRAFT, TODO, 오래된 계획을 정기 점검합니다.
