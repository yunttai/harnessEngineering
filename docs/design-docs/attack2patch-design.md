# Attack2Patch 설계

- 상태: DRAFT
- 관련 PRD: `../product-specs/attack2patch-prd.md`

## 처리 흐름

```text
HTTP 로그 → 공격 탐지 → Flask 라우트 매핑 → 취약 코드 탐지
→ 패치 후보 → 사용자 승인 → 격리 검증 → 이미지 빌드
→ 배포 승인 → 재배포 → 헬스체크/재공격 → 완료 또는 롤백
```

## 설계 제약

- 지원 대상은 Flask, SQLite, SQL Injection으로 제한한다.
- 패치는 허용된 작업 복사본에만 적용한다.
- 테스트 통과 전 이미지 빌드와 배포를 허용하지 않는다.
- 배포 전 기존 정상 이미지 태그를 보존한다.
