# 안정성 및 복구 기준

- 빌드 실패는 실행 중 서비스에 영향을 주지 않아야 한다.
- 신규 컨테이너는 `/health`, 정상 요청, 재공격 검증을 모두 통과해야 한다.
- 검증 실패 시 60초 이내에 이전 정상 이미지로 롤백한다.
- 배포와 롤백 결과는 이벤트 ID 및 이미지 태그와 함께 기록한다.

## 상태 전이와 실패 처리

- Build는 현재 서비스 교체 전에 완료되므로 실패 시 running service를 건드리지 않는다.
- `GENERATED → APPROVED → VALIDATED` 순서를 벗어난 후보는 배포할 수 없다.
- Compose 호출이 시작된 뒤 발생한 모든 오류는 이전 image rollback을 시도한다.
- 신규/rollback 컨테이너는 즉시 판정하지 않고 최대 30초 동안 `/health` readiness를 polling한다.
- 후보 검증 실패와 rollback 검증 결과는 서로 덮어쓰지 않고 함께 저장한다.
- 자동 rollback은 이전 서비스 `/health`가 성공해야 `ROLLED_BACK`으로 기록한다.
- 수동 rollback은 완료된 배포와 명시적 승인에만 허용된다.
- 모든 저장은 `state_transitions`에 entity, event ID, 시간, 상태와 오류를 추가한다.

단위/E2E 테스트는 build 실패 무영향, 성공 배포, 공격 검증 실패 자동 rollback과 수동 rollback을
가짜 Runtime adapter로 결정론적으로 검증한다. 실제 Docker daemon에서도 성공 배포 5.767초,
수동 rollback 2.666초, 강제 candidate verdict 실패 자동 rollback 7.156초를 확인했다.
