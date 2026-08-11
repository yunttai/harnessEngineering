# CWE-89 — SQL Injection

## 취약 원인

공격자 제어 값이 SQL 문자열 구조에 직접 삽입됩니다.

## 안전 수정

- DB driver의 parameterized query 사용
- value는 placeholder와 parameter tuple/dict로 분리
- table/column identifier는 parameterization 대상이 아니므로 고정 mapping/allowlist 사용
- ORM 사용 시 raw SQL escape hatch를 피함
- validation은 도메인 제약에 사용하되 parameterization을 대체하지 않음

## 검증

- malicious payload가 query 문자열에 포함되지 않음
- payload가 parameter로 전달됨
- 정상 조회 기능 유지
- 동일 scanner finding 제거
- error-based/boolean-based payload가 쿼리 구조를 바꾸지 못함
