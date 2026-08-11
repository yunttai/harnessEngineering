# ADR-0002: Verification-Driven Patching

- 상태: ACCEPTED
- 결정일: 2026-08-11

## 배경

코드 생성 모델은 문법적으로 그럴듯하지만 기능·보안 면에서 잘못된 패치를 만들 수 있습니다.
Scanner 결과가 사라지는 것만으로 실제 공격이 차단되었다고 보기도 어렵습니다.

## 결정

PatchCandidate를 원본에 바로 적용하지 않고 임시 복사본에서 다음 순서로 평가합니다.

1. build
2. functional regression
3. security re-scan
4. exploit mitigation
5. 변경 크기·스타일 점수

필수 게이트와 점수는 분리합니다.

## 검증

- [x] sandbox copy
- [x] compileall
- [x] opt-in pytest
- [x] re-scan
- [x] CWE-89 구조적 mitigation check
- [x] score model
