# 프론트엔드 규약

- 공격 목록, 코드 Diff, 검증 결과, 배포 상태를 분리해 표시한다.
- 승인 버튼은 서버 측 상태와 동일한 조건으로 활성화한다.
- 핵심 UI 요소에는 안정적인 `data-testid`를 부여한다.
- 성공, 실패, 롤백 상태를 색상에만 의존하지 않고 텍스트로 표시한다.

## 고정 테스트 ID

| 화면 | `data-testid` |
| --- | --- |
| 이벤트 목록 | `attack-event-list`, `attack-event-row`, `event-status` |
| 공격 상세 | `attack-detail`, `failure-reason` |
| 코드 탐지 | `code-finding` |
| 패치 | `patch-panel`, `patch-status`, `patch-diff`, `patch-generate`, `patch-approve`, `patch-reject` |
| 검증 | `patch-validate`, `validation-panel`, `validation-<gate>` |
| 배포 | `deployment-panel`, `deploy-approve`, `deployment-status`, `manual-rollback` |

패치 승인 버튼은 `GENERATED`, 검증 버튼은 `APPROVED`, 배포 승인 버튼은 `VALIDATED`, 수동
rollback 버튼은 `COMPLETED`에서만 활성화한다. 동일 조건을 API Service가 다시 검사하므로 DOM
변조로 상태 게이트를 우회할 수 없다.
