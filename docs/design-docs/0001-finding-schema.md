# ADR-0001: 공통 Finding Schema

- 상태: ACCEPTED
- 결정일: 2026-08-11

## 배경

Scanner마다 파일 위치, CWE, severity, rule, trace 표현이 다릅니다. 후속 분석과 패치가 특정
도구 형식에 결합되면 scanner를 추가할수록 복잡도가 증가합니다.

## 결정

모든 scanner 출력을 `Finding` Pydantic 모델로 변환합니다. 원시 결과는 evidence에 보존하고,
정규화 필드는 사실과 추론을 구분합니다.

## 불변 조건

- finding_id/fingerprint는 결정적
- file은 대상 root 기준 상대 경로
- line은 1-based
- raw evidence는 크기 제한
- parser 실패는 별도 오류
- source/sink가 없으면 null

## 검증

- [x] 모델 테스트
- [x] JSON Schema 생성
- [x] 내장 scanner
- [x] Semgrep adapter
