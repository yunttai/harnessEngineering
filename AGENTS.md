# AGENTS.md

이 파일은 에이전트를 위한 짧은 저장소 지도입니다. 상세 지식은 `docs/`를 단일 기록 시스템으로 사용합니다.

## 시작 순서

1. `docs/product-specs/attack2patch-prd.md`
2. `ARCHITECTURE.md`
3. `docs/design-docs/attack2patch-design.md`
4. `docs/design-docs/attack2patch-threat-model.md`
5. `docs/exec-plans/active/attack2patch-mvp.md`
6. `docs/SECURITY.md`, `docs/RELIABILITY.md`

## 리포지터리 구조

```text
docs/                 제품 요구사항, 설계, 계획, 보안 지식
src/attack2patch/     Attack2Patch 제품 코드
demo-app/             의도적으로 취약한 격리형 Flask 데모 앱
rules/                로그 및 코드 탐지 규칙
tests/                단위, 통합, E2E 검증
scripts/              품질 검사와 데모 실행 도구
docker/               Attack2Patch 이미지 정의
docker-compose.yml    로컬 데모 배포 구성
```

## 작업 규칙

- MVP는 Python Flask, SQLite, SQL Injection, Docker Compose만 지원한다.
- 공격 입력은 신뢰하지 않고 스키마로 파싱한다.
- 패치 및 배포는 사용자 승인 없이는 수행하지 않는다.
- Docker 제어 인터페이스를 외부 네트워크에 노출하지 않는다.
- `demo-app/`의 취약 코드를 일반 서비스 코드로 복사하지 않는다.
- 변경 후 테스트, 보안 재검사, 헬스체크를 수행한다.
- 제품 동작이나 범위가 바뀌면 PRD와 관련 설계 문서를 함께 갱신한다.

## 완료 조건

- 정상 요청 회귀 테스트 통과
- SQL Injection 재현 테스트 통과
- 정적 분석 재검사 통과
- 신규 컨테이너 헬스체크 통과
- 실패 시 이전 이미지 롤백 검증
