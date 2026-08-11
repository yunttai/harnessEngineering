# CWE-78 — OS Command Injection

- shell 문자열 조립을 피하고 argv list로 실행
- `shell=True`, `os.system`, `popen` 문자열 명령을 제거
- 실행 파일과 option을 고정
- 사용자 값은 허용 형식으로 파싱
- 가능하면 shell 대신 라이브러리 API 사용
- 환경 변수와 PATH를 최소화
