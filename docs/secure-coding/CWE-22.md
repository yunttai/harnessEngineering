# CWE-22 — Path Traversal

- 신뢰 root를 resolve
- 입력 경로를 join한 뒤 resolve
- 결과가 root 내부인지 `relative_to`로 확인
- symlink 정책을 명시
- 사용자 입력 파일명과 서버 저장 경로를 분리
- 단순 `..` 문자열 제거를 수정으로 인정하지 않음
