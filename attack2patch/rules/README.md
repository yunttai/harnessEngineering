# Rules

- `semgrep/` — 로컬 Semgrep 규칙

Scanner rule은 Finding을 생성하는 도구이며 자동 패치 정책과 동일하지 않습니다. Rule 변경으로
Finding을 숨기는 방식은 패치로 인정하지 않습니다.

규칙은 source/sink 패턴을 탐지하는 데만 사용합니다. 수정 후보는 parameterization, 안전한 API,
입력 검증 같은 언어·프레임워크의 시큐어코딩 원칙을 적용하고 독립 re-scan과 exploit 검증을
통과해야 합니다.
