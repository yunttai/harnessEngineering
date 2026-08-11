# Attack2Patch 배포 롤백 런북

이 문서는 `CommandDeploymentProvider`가 staging/canary/promotion 실행 전에 존재 여부를 확인하는 최소
운영 계약입니다. 실제 환경별 명령은 `attack2patch/config/harness.yaml`의 argv 목록으로만
설정하며 shell 문자열 보간을 사용하지 않습니다. 실행 제품에는 같은 계약을
`attack2patch/runbooks/rollback.md`로 함께 배포합니다.

## 사전 조건

- 대상 커밋과 직전 안정 커밋 SHA를 기록한다.
- staging health/readiness 검증이 통과해야 canary를 시작한다.
- canary 트래픽 비율, 관측 시간, 오류율·지연 임계값을 변경 승인에 기록한다.
- rollback 명령과 담당자가 준비되지 않으면 배포하지 않는다.

## 롤백 조건

- 보안 재현 테스트 재실패
- 오류율 또는 지연이 승인 임계값 초과
- 핵심 회귀 테스트 실패
- 데이터 무결성 이상 또는 예상하지 못한 권한 변화

## 절차

1. canary 트래픽을 중단한다.
2. 설정된 `rollback_command`를 argv 그대로 실행한다.
3. readiness와 핵심 회귀·보안 테스트를 다시 실행한다.
4. 실행 명령, exit code, 로그 excerpt, 영향 시간을 run evidence에 연결한다.
5. 실패한 배포를 자동 재시도하지 않고 사람 검토로 전환한다.
