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
| 내장 Python 탐지 | B | 좁은 CWE-22/78/89/502/secret 지원, 언어·framework 범위 제한 |
| 외부 scanner | B | Semgrep/Trivy/Gitleaks/SARIF parser, 실제 binary matrix 필요 |
| 분석 | B | 결정적 CWE 분석과 세 가지 local CLI structured-output provider, interprocedural flow 필요 |
| 패치 생성 | B | CWE-22/78/89/502 fail-closed AST codemod와 구조화 LLM TextEdit provider |
| 검증 | A | local-copy/Docker build·test·re-scan, manifest/DAST와 CWE별 독립 AST oracle |
| 격리 | A | 실제 Docker에서 source read-only/workspace writable, internal network readiness와 cleanup 검증 |
| DAST | A | 실제 containerized ZAP 리포트 파싱과 Nuclei baseline 1→patched 0 differential 검증 |
| Git/PR | B | 설치/repository/permission smoke 구현; 실제 credential 실행 evidence 필요 |
| 배포 | A | pushed commit gate, 실제 Docker staging/canary/bounded observation/promotion PASS와 실패 rollback 테스트 |
| 문서 드리프트 | A | check-links/doc-gardening |
| 하네스 자체 테스트 | A | scanner/patcher/scoring/orchestrator 테스트 |

## C 이하 처리

C/D 항목은 `exec-plans/tech-debt-tracker.md`와 연결하고, production 자동화의 선행 조건으로
취급합니다.
