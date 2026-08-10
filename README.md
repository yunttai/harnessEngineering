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
docker compose up --build
```

대시보드는 `http://127.0.0.1:8080`, 격리된 데모 앱은 `http://127.0.0.1:5000`에서 접근합니다.
