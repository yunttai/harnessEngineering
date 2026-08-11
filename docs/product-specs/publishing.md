# 스펙: Publishing

- 상태: IMPLEMENTED
- 소유: Runtime, UI

## 목표

검증된 후보를 짧은 Git branch와 draft PR로 전달합니다.

## 수용 기준

- [x] clean tree 검사
- [x] original commit SHA 기록
- [x] verified candidate만 적용
- [x] branch naming
- [x] 의도된 파일만 stage
- [x] candidate secret scan
- [x] PR 본문에 Finding/검증/위험/rollback
- [x] CI 링크
- [x] push/PR 별도 승인
- [x] GitHub App 최소 권한

원격 push/PR은 기본 비활성이며 설정 정책과 `publish` CLI의 독립 옵션이 모두 있어야 합니다.
GitHub App 인증은 App JWT를 installation token으로 교환하고 draft PR만 생성합니다.
