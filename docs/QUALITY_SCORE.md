# QUALITY_SCORE.md — 품질 등급

## 등급

| 등급 | 의미 |
| --- | --- |
| A | 불변 조건·문서·테스트·evidence가 충분 |
| B | 핵심 동작은 검증되었으나 일부 provider/격리 기능 미완성 |
| C | 중요한 검증 또는 경계가 문서에만 있고 기계적 강제 부족 |
| D | 안전하지 않거나 재현 불가 |

## 현재 상태

| 영역 | 등급 | 근거 / 다음 작업 |
| --- | --- | --- |
| 맵·지식베이스 | A | AGENTS/ARCHITECTURE/docs와 링크 검사 |
| Finding Schema | A | Pydantic 모델과 JSON Schema 생성 |
| 내장 Python 탐지 | B | CWE-89/78/502/secret 지원, 언어 범위 제한 |
| 외부 scanner | B | Semgrep/Trivy/Gitleaks/SARIF parser, 실제 binary matrix 필요 |
| 분석 | B | 결정적 CWE 분석과 세 가지 local CLI structured-output provider, interprocedural flow 필요 |
| 패치 생성 | B | CWE-89 codemod와 CLI schema/hash/range 검증 LLM TextEdit provider |
| 검증 | B | local-copy build/test/re-scan/구조 검증 |
| 격리 | C | Docker/VM security boundary 미구현 |
| Git/PR | B | 로컬 branch/commit/push와 mock 검증 GitHub App draft PR |
| 배포 | C | argv staging/canary/rollback provider와 runbook, 실제 관측 미연결 |
| 문서 드리프트 | A | check-links/doc-gardening |
| 하네스 자체 테스트 | A | scanner/patcher/scoring/orchestrator 테스트 |

## C 이하 처리

C/D 항목은 `exec-plans/tech-debt-tracker.md`와 연결하고, production 자동화의 선행 조건으로
취급합니다.
