# 에이전트 팀

실제 정의는 `.opencode/agent/<name>.md`에 있고, 이 문서는 협업 규약을 설명합니다.

## 구성

| Agent | 모드 | 편집 | 핵심 책임 |
| --- | --- | --- | --- |
| orchestrator | primary | 허용 | 목표 분해, 위임, 루프, 자율성 게이트 |
| detector | subagent | 금지 | scanner 실행, Finding 정규화 |
| analyzer | subagent | 금지 | source→sink와 root cause 복원 |
| patcher | subagent | 허용 | 최소 패치 후보 생성 |
| verifier | subagent | 금지 | 격리 build/test/re-scan/exploit |
| reviewer | subagent | 금지 | 요구사항·evidence 독립 검토 |
| security | subagent | 금지 | 새 취약점·우회 독립 검토 |
| committer | subagent | 금지 | 승인된 변경의 branch/commit/PR |
| deployer | subagent | 금지 | staging/canary/observation/promotion/rollback |

## 협업 루프

```text
detector → analyzer → patcher → verifier
                           ↑         │
                           └─ FAIL ──┘
                               │ PASS
                               ▼
                       reviewer + security
                               │
                        BLOCK ──┘
                               │ APPROVED
                               ▼
                          committer
                               │
                     explicit approval
                               ▼
                           deployer
```

## 역할 분리

- detector/analyzer는 코드를 편집하지 않습니다.
- patcher는 후보를 만들지만 자신의 후보를 승인하지 않습니다.
- verifier는 원본이 아닌 임시 복사본에서 실행합니다.
- reviewer와 security는 서로 다른 관점의 독립 게이트입니다.
- committer는 코드를 새로 수정하지 않습니다.
- deployer는 MVP 기본 루프에서 호출되지 않습니다.

## 실패 피드백

Verifier는 단순 `FAIL` 대신 다음을 반환합니다.

```json
{
  "stage": "functional_test",
  "status": "FAIL",
  "command": ["python", "-m", "pytest", "-q"],
  "exit_code": 1,
  "failed_test": "test_get_user",
  "stderr_excerpt": "...",
  "candidate_id": "PATCH-...",
  "artifact": ".autopatch/runs/.../evaluations.json"
}
```

Patcher는 이 evidence만을 근거로 다음 후보를 생성합니다. 최대 시도 횟수를 넘으면 사람 검토로
전환합니다.

## 에스컬레이션 기준

- 대상 범위/허가가 불명확함
- 원본 작업 트리가 더러움
- scanner 결과가 서로 충돌함
- 인증/인가·비즈니스 로직을 정책 결정 없이 수정해야 함
- 테스트가 없거나 신뢰할 수 없음
- 새 dependency/DB migration/API breaking change 필요
- 재현은 되지만 안전한 최소 패치가 불명확함
- production 배포
