# ARCHITECTURE.md

Attack2Patch는 다음 단방향 레이어를 사용합니다.

```text
Types → Config → Repo → Service → Runtime → UI
```

- Types: 입력 및 상태 스키마
- Config: 환경 설정 파싱
- Repo: 이벤트와 배포 이력 저장
- Service: 공격 탐지, 코드 매핑, 패치 및 검증 로직
- Runtime: 로그, 테스트, Docker 빌드·배포·롤백 어댑터
- UI: API와 대시보드

`demo-app/`은 제품 코드와 분리된 시연 대상입니다. 상세 설계는 `docs/design-docs/attack2patch-design.md`를 따릅니다.
