# Attack2Patch 설계

- 상태: DRAFT
- 관련 PRD: `../product-specs/attack2patch-prd.md`

## 처리 흐름

```text
HTTP 로그 → 공격 탐지 → Flask 라우트 매핑 → 취약 코드 탐지
→ 패치 후보 → 사용자 승인 → 격리 검증 → 이미지 빌드
→ 배포 승인 → 재배포 → 헬스체크/재공격 → 완료 또는 롤백
```

## 구현 구성

- `Types`: 외부 필드 거부, HTTP 메서드·상태 Enum, 이벤트/탐지/패치/배포 스키마
- `Config`: SQLite, 허용된 로컬 데모 URL, 작업 디렉터리, Compose 파일과 기준 이미지 검증
- `Repo`: SQLite 이벤트·탐지·패치·배포·상태 전이 이력
- `Service`: SQL Injection 규칙, Flask AST 라우트 매핑, 코드 스캔, Diff와 승인 상태 머신
- `Runtime`: JSON Lines 로그 tail, 후보 테스트, Docker build, Compose 교체, HTTP 검증
- `UI`: REST API, 상태 기반 버튼과 `data-testid`가 있는 서버 렌더링 대시보드

UI 조립 지점에서 Runtime 구현을 Service Protocol에 주입한다. `scripts/check_architecture.py`가
`Types → Config → Repo → Service → Runtime → UI` 순서의 역방향 import를 차단한다.

## 로그 수집

데모 앱은 요청 완료 시 스키마가 고정된 JSON Lines 레코드를 공유 볼륨에 기록한다. 토큰,
쿠키, 비밀번호 계열 키는 기록 전에 마스킹한다. Attack2Patch collector는 시작 시 기존 파일
끝에서 읽기 시작하고 신규 줄만 Pydantic 스키마로 파싱한다. 알 수 없는 필드나 손상된 줄은
저장하지 않는다.

## 패치와 검증

패치 생성은 원본 내용, SHA-256, unified Diff와 이유만 저장한다. 명시적 승인 후 UUID 기반
작업 디렉터리에 `demo-app/`을 복사하고, 원본 hash와 승인된 Diff가 일치할 때만 고정 규칙을
적용한다. 검증 게이트는 Python 구문, 후보 단위 테스트, 정상 사용자 조회, 5개 공격 재현,
동일 AST 정적 재검사이며 하나라도 실패하면 `VALIDATION_FAILED`로 종료한다.

## 배포와 복구

검증된 후보만 내부 UUID로 만든 allowlist 이미지 태그로 build한다. Build 실패는 Compose를
호출하지 않는다. 배포 직전에 최근 완료 이미지 또는 기준 이미지를 기록하며, 고정된
`demo-app` 서비스만 argument-array Docker/Compose 명령으로 재생성한다. `/health`, 정상 요청,
5개 재공격 중 하나라도 실패하면 이전 이미지를 복구하고 후보·롤백 검증 결과를 모두 저장한다.
Docker socket은 Runtime 컨테이너 내부 Unix socket으로만 마운트되고 네트워크에 공개되지 않는다.

## 설계 제약

- 지원 대상은 Flask, SQLite, SQL Injection으로 제한한다.
- 패치는 허용된 작업 복사본에만 적용한다.
- 테스트 통과 전 이미지 빌드와 배포를 허용하지 않는다.
- 배포 전 기존 정상 이미지 태그를 보존한다.
- 패치 승인과 배포 승인은 별개의 서버 측 상태 전이로 처리한다.
- 후보 image tag, 서비스 이름, Compose 파일은 HTTP 입력으로 받지 않는다.
- Host와 Runtime 컨테이너는 동일한 allowlist project name `attack2patch`와 명시적 volume name을 사용한다.
