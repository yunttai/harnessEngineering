# 보안 기준

- 패치와 배포에는 명시적 승인이 필요하다.
- 토큰, 쿠키, 비밀번호는 저장 전에 마스킹한다.
- 외부 입력을 셸 명령이나 파일 경로에 직접 삽입하지 않는다.
- 수정 가능 범위를 격리된 작업 디렉터리로 제한한다.
- Docker 제어 인터페이스를 외부에 노출하지 않는다.
- 테스트 및 재스캔 실패 시 fail-closed로 중단한다.
- 실제 비밀정보를 저장소에 커밋하지 않는다.

## 구현 증거

- `HttpLogRecord`는 알 수 없는 필드, 잘못된 IP/경로/시간대를 거부한다.
- 데모 로그 writer와 수집 경계에서 민감 키를 마스킹한다.
- `ensure_repository_path`와 UUID workspace가 원본 및 경로 이탈 수정을 차단한다.
- patch SHA-256과 Diff를 승인 시 다시 비교한다.
- 검증 완료 시 전체 build context manifest hash를 저장하고 image build 직전에 다시 비교한다.
- Docker build/Compose는 shell 없이 고정 인자와 내부 생성 image tag만 사용한다.
- `scripts/check-secrets.sh`와 `scripts/check_architecture.py`를 `scripts/check.sh`에서 실행한다.

Docker socket은 호스트 권한이 큰 자산이다. MVP에서는 daemon을 제품 이미지에 설치하거나
외부 네트워크에 노출하지 않고 Attack2Patch 컨테이너에 Unix socket으로만 제공한다. Runtime adapter는 `demo-app` 서비스의
build, recreate, rollback 명령만 구성한다. 운영 환경용 권한 분리는 비목표이며 README의
데모 전용 경고를 따른다.
