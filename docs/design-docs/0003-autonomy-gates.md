# ADR-0003: 자율성 게이트

- 상태: ACCEPTED
- 결정일: 2026-08-11

## 결정

다음 동작을 하나의 `auto=true`로 묶지 않고 독립 게이트로 분리합니다.

- scan
- 대상 코드 테스트 실행
- 원본 패치 적용
- branch
- commit
- push
- pull request
- DAST
- deploy

## 이유

각 동작의 위험과 필요한 권한이 다릅니다. scan을 허용했다고 production deploy까지 묵시적으로
허용된 것은 아닙니다.

## 기본값

scan과 dry-run candidate만 활성화합니다. 나머지는 비활성입니다.
