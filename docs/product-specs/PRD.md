# PRD: Attack2Patch

- 상태: ACCEPTED
- 작성일: 2026-08-11
- 대상: 로컬·허가된 애플리케이션 소스 저장소
- 원본: `../references/source-project-plan.md`

## 1. 배경

기존 DevSecOps 흐름에서는 scanner가 취약점 위치를 알려준 뒤 개발자가 실제 원인, 악용 가능성,
수정 방식, 회귀 여부, 제거 여부를 다시 판단해야 합니다. 본 제품은 탐지 이후의 분석·패치·검증·
전달을 하나의 자동화 하네스로 연결합니다.

## 2. 목표

- 여러 scanner 결과를 공통 Finding Schema로 통합
- source→sink와 root cause 분석
- 시큐어코딩 기반 최소 패치 후보 생성
- build, regression, re-scan, exploit mitigation 기반 후보 검증
- 검증 실패를 다음 후보 생성에 피드백
- 검증된 패치의 branch/PR 전달
- 모든 판단의 evidence 보존

## 3. 비목표

MVP에서 다음은 기본 자동 완료 범위가 아닙니다.

- production 무인 배포
- 허가되지 않은 원격 대상 DAST
- 모든 언어·프레임워크 지원
- 인증/인가·IDOR·비즈니스 로직의 일반 자동 수정
- scanner 경고만으로 실제 취약점 확정
- LLM 응답만으로 수정 완료 판정

## 4. 사용자

| 사용자 | 필요 |
| --- | --- |
| AppSec/DevSecOps 엔지니어 | 반복 Finding의 수정·검증 자동화 |
| 개발자 | 리뷰 가능한 최소 diff와 실패 원인 |
| 보안 연구자 | 후보·검증 결과·성공률 실험 데이터 |
| 운영 담당자 | staging/canary/rollback이 포함된 전달 정보 |

## 5. 기능 요구사항

| ID | 요구사항 | 우선순위 | 수용 기준 |
| --- | --- | --- | --- |
| FR-01 | 로컬 저장소를 scan | P0 | 예제 CWE-89가 Finding Schema로 출력 |
| FR-02 | Multi-scanner 결과 정규화 | P0 | scanner별 결과가 동일 모델로 parse |
| FR-03 | Finding 중복 제거 | P0 | 같은 fingerprint가 한 건으로 병합 |
| FR-04 | root cause 분석 | P0 | source, sink, 원인, 추천 수정 출력 |
| FR-05 | 최소 패치 후보 | P0 | TextEdit와 unified diff 생성 |
| FR-06 | 후보 build 검증 | P0 | 임시 복사본 compile 결과 기록 |
| FR-07 | regression 검증 | P0 | opt-in 테스트의 exit code/evidence 기록 |
| FR-08 | security re-scan | P0 | 동일 취약점 잔존 여부 판정 |
| FR-09 | exploit mitigation | P0 | 가능한 CWE에 구조/동적 검증 결과 기록 |
| FR-10 | 후보 점수·선택 | P0 | 40/30/15/10/5 점수와 필수 게이트 적용 |
| FR-11 | 실패 피드백 | P1 | stage별 실패 사유가 다음 시도 입력으로 저장 |
| FR-12 | 원본 적용 | P1 | VERIFIED + 명시적 apply에서만 hash 검증 후 반영 |
| FR-13 | branch/PR | P1 | verified evidence를 포함한 draft PR 생성 가능 |
| FR-14 | API | P1 | scan/run 상태를 FastAPI로 요청 가능 |
| FR-15 | staging/canary | P2 | provider와 rollback runbook 연결 |

## 6. 비기능 요구사항

### 보안

- 로컬 경로만 기본 허용
- dry-run 기본
- shell command interpolation 금지
- secret redaction
- 대상 테스트 실행 opt-in
- 원본 SHA 불일치 시 적용 중단
- DAST authorization gate

### 안정성

- 모든 외부 도구 timeout
- scanner 실패와 결과 없음 분리
- run별 evidence 디렉터리
- 동일 입력에 대한 결정적 fingerprint
- 한 Finding 실패가 다른 Finding 결과를 손상시키지 않음

### 유지보수

- Types→Config→Repo→Service→Runtime→UI 레이어 검사
- Provider 기반 scanner/LLM/Git/Deploy 교체
- 문서 링크와 스키마 CI 검증

## 7. MVP 1 수용 기준

- [x] 내장 Python scanner가 예제 CWE-89 탐지
- [x] Finding JSON 생성
- [x] 결정적 root cause 분석
- [x] CWE-89 parameterized query 후보 생성
- [x] 임시 복사본 build
- [x] security re-scan
- [x] 구조적 exploit mitigation 확인
- [x] unified diff 출력
- [x] 하네스 자체 pytest
- [x] 실제 LLM structured output provider
- [x] GitHub App PR provider

## 8. 상태 및 실패 상태

정상 상태:

```text
CREATED → DETECTING → DETECTED → ANALYZING
→ PATCH_GENERATING → VERIFYING → VERIFIED → APPLIED → PR_CREATED → DEPLOYED
```

실패/중단:

```text
DETECTION_FAILED
ANALYSIS_FAILED
PATCH_FAILED
BUILD_FAILED
TEST_FAILED
SECURITY_TEST_FAILED
NEEDS_HUMAN_REVIEW
PUBLISH_FAILED
DEPLOY_FAILED
```

## 9. 평가 지표

- Detection Precision
- Patch Success Rate = 검증 통과 패치 / 전체 후보
- Security Fix Rate = 패치 후 실제 제거된 Finding / 패치 대상
- Regression Rate = 패치 후 기존 테스트 실패 / 적용 후보
- Exploit Mitigation Rate = 재현 공격 차단 / 재현 가능 취약점
- Autonomous Patch Rate = 사람 수정 없이 검증 완료 / 전체 대상
- 평균 변경 라인 수
- 평균 재시도 수
- 검증 SKIPPED 비율

## 10. 주요 위험

| 위험 | 영향 | 대응 |
| --- | --- | --- |
| scanner false positive | 잘못된 패치 | analysis와 exploitability 분리 |
| LLM hallucination | 코드 손상 | structured output, 최소 diff, 실제 검증 |
| 대상 테스트 실행 | 악성 코드 실행 | 기본 off, 격리 provider |
| scanner 우회 패치 | 취약점 잔존 | 독립 security 리뷰와 exploit 검증 |
| 복잡 business logic | 오수정 | 사람 검토 |
| 배포 자동화 | 운영 장애 | MVP 비목표, staging/canary/rollback |
