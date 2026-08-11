# DESIGN.md — 골든 룰

## 1. 경계에서 파싱

Scanner JSON, SARIF, YAML, LLM 출력, subprocess 결과, API 입력을 추측한 dictionary로
사용하지 않습니다. `src/autopatch/types/`의 스키마로 파싱하고 실패를 명시합니다.

## 2. Evidence가 최종 판정

에이전트의 설명보다 다음 실제 결과를 우선합니다.

- exit code
- stdout/stderr
- 재스캔 Finding
- 회귀 테스트
- exploit replay
- 파일 hash
- unified diff

## 3. 최소 변경

- 전체 파일을 다시 쓰지 않습니다.
- 구조화된 `TextEdit`와 원본 SHA를 사용합니다.
- unrelated formatting/refactor를 섞지 않습니다.
- 변경 크기는 점수와 사람 검토 기준에 반영합니다.

## 4. Scanner 우회 금지

다음은 수정으로 인정하지 않습니다.

- rule disable/noqa 추가
- scanner ignore/exclude 확대
- 취약 코드를 dead code로 보이게만 변경
- 테스트 삭제·assert 완화
- 오류를 삼켜 공격 동작을 숨김
- 사용자 입력을 로그로만 남기고 그대로 sink에 전달

## 5. 검증 가능한 수용 기준

각 기능과 패치는 자동 실행 가능한 기준을 가집니다. 검증할 수 없는 요구는 구현 전에 테스트
또는 관측 지점을 설계합니다.

## 6. Service와 Runtime 분리

순수 선택·상태 전이 로직은 Service에, subprocess/AST/git/filesystem 동작은 Runtime에 둡니다.
Service가 구체 외부 도구를 직접 생성하지 않습니다.

## 7. 결정적 동작 우선

가능한 경우 AST, codemod, schema, rule 기반 처리를 우선하고 LLM은 context 복원과 후보
다양화에 사용합니다. 동일 입력에 대한 재현 가능성을 보존합니다.

## 8. 지원하지 않는 것은 명시적으로 거부

자동 수정 범위를 넓게 가장하지 않습니다. 근거가 부족한 취약점은
`NEEDS_HUMAN_REVIEW`로 남깁니다.

## 9. 생성 파일

`docs/generated/`와 `schemas/`는 생성 명령을 통해 갱신합니다. 수동 변경이 필요하면 먼저 생성
도구를 수정합니다.

## 10. 모든 실패는 산출물

실패 로그와 탈락 이유는 다음 후보와 연구 평가에 필요한 데이터입니다. 삭제하거나 성공 결과로
덮어쓰지 않습니다.
