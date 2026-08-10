# Attack2Patch

SQL Injection 공격 로그를 취약 코드와 연결하고, 검증된 패치를 Docker 이미지로 재배포하는 3일 MVP입니다.

## 문서 시작점

- 작업 규칙과 저장소 지도: `AGENTS.md`
- 아키텍처: `ARCHITECTURE.md`
- 제품 요구사항: `docs/product-specs/attack2patch-prd.md`
- 실행 계획: `docs/exec-plans/active/attack2patch-mvp.md`
- 문서 색인: `docs/index.md`

## 주의

이 저장소의 `demo-app/`은 보안 교육과 제품 시연을 위해 의도적으로 취약한 코드를 포함할 수 있습니다. 외부 네트워크나 운영 환경에 배포하지 마세요.

## 로컬 실행 준비

```bash
cp .env.example .env
docker compose --project-name attack2patch up --build
```

대시보드는 `http://127.0.0.1:8080`, 격리된 데모 앱은 `http://127.0.0.1:5000`에서 접근합니다.
데모 앱 요청은 공유된 JSON Lines 로그를 통해 자동 수집되며, 공격은 다음 명령으로 재현합니다.

```bash
./scripts/run-demo-attack.sh
```

대시보드에서 패치를 생성하고 Diff를 검토한 뒤 패치 승인과 격리 검증을 순서대로 수행합니다.
모든 검증이 성공한 경우에만 배포 승인 버튼이 활성화됩니다. 패치 승인 전에는 원본
`demo-app/`이 변경되지 않으며, 배포 검증 실패 시 기록된 이전 이미지로 자동 롤백합니다.

## 검증

```bash
./scripts/check.sh
docker compose --project-name attack2patch config --quiet
```

`scripts/check.sh`는 테스트, 구문 검사, Ruff, 레이어 의존성 검사와 비밀정보 검사를 실행합니다.
Docker 이미지 빌드·헬스체크·롤백 E2E에는 실행 중인 Docker daemon이 필요합니다.

실제 자동 rollback 리허설은 stack이 실행 중일 때 다음처럼 수행합니다.

```bash
PYTHONPATH=src python scripts/verify_docker_rollback.py
```
