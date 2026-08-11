# Attack2Patch Rollback Runbook

이 문서는 `deployment.rollback_command`가 구현해야 하는 최소 운영 계약입니다. 실제 환경별
명령과 소유자는 배포 전에 이 파일을 교체하거나 별도 검토된 runbook 경로를 설정합니다.

## Trigger

- staging, canary 또는 production promotion command의 non-zero exit/timeout
- observation command의 첫 non-zero exit/timeout
- 관측 창 또는 최소 PASS 수를 만족하기 전 최대 시도 횟수 소진

## Required behavior

1. 현재 release와 직전 정상 release 식별자를 확인한다.
2. traffic과 workload를 직전 정상 release로 되돌린다.
3. schema/data migration은 사전에 검토된 역방향 절차만 수행한다.
4. rollback command는 복구 확인까지 성공해야 exit code 0을 반환한다.
5. stdout/stderr에는 secret을 출력하지 않고 배포 ID와 관측 링크만 남긴다.

## Evidence

Attack2Patch는 rollback argv, exit code, duration, 제한된 stdout/stderr와 원래 실패 phase를
`RunReport.deployments`와 state event에 보존합니다. rollback 자체가 실패하면 run은
`DEPLOY_FAILED`로 유지되며 운영자 개입이 필요합니다.
