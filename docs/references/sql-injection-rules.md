# SQL Injection 탐지 규칙 참고

MVP는 테스트 fixture에 정의된 제한된 패턴만 지원합니다. 규칙은 `rules/`의 YAML 파일이 실행 기준입니다.

- 논리식 우회 패턴
- UNION SELECT
- SQL 주석
- 비정상 따옴표
- 시간 지연 함수
