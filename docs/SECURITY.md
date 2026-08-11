# SECURITY.md — 하네스 보안 기준

## 신뢰 경계

```text
사용자 CLI/API 입력
  → 대상 경로 정책
  → Scanner/프로세스
  → 정규화기
  → 패치 후보
  → 임시 복사본 실행
  → Git/PR/배포 공급자
```

각 경계에서 경로, 스키마, 명령, 권한을 검증합니다.

## 허가 범위

- 기본 입력은 로컬 경로만 허용합니다.
- DAST, exploit replay, 외부 URL 요청은 `authorized_targets`에 명시된 대상만 허용합니다.
- 대상이 허가되었는지 판단할 수 없으면 실행하지 않습니다.
- CTF·교육용 예제는 로컬 파일과 로컬 프로세스 범위에서만 다룹니다.

## 대상 코드 실행

대상 저장소의 build/test/security test는 해당 저장소의 코드를 실행할 수 있습니다.

- 기본 설정은 `execute_project_tests: false`입니다.
- 신뢰할 수 있는 허가된 저장소에서만 `--execute-tests`를 사용합니다.
- 신뢰할 수 없는 저장소는 Docker/VM/Firecracker 공급자를 연결합니다.
- 로컬 복사 sandbox는 파일 격리일 뿐 커널 보안 경계가 아닙니다.
- timeout, cwd, 환경 변수 allowlist, 네트워크 비활성 정책을 사용합니다.

## 명령 실행

- `shell=True`를 사용하지 않습니다.
- argv list로 실행합니다.
- 명령 이름은 registry와 allowlist에 있어야 합니다.
- 사용자 입력을 명령 문자열로 연결하지 않습니다.
- stdout/stderr 크기와 timeout을 제한합니다.

## 경로 안전성

- 대상 root를 `resolve()`한 뒤 모든 파일이 root 내부인지 확인합니다.
- symlink escape를 거부합니다.
- `.git`, `.venv`, `node_modules`, `.autopatch`, build artifact를 기본 제외합니다.
- binary와 과대 파일은 패치하지 않습니다.
- 후보 적용 전 원본 SHA-256을 재검증합니다.

## Secret

- `.env`, token, private key를 커밋하지 않습니다.
- evidence에는 전체 환경 변수를 기록하지 않습니다.
- 로그는 알려진 secret 패턴을 redact합니다.
- Git/PR 공급자는 최소 권한 token을 사용합니다.
- `scripts/check-secrets.py`를 CI와 커밋 전에 실행합니다.

## 패치 보안 검증

- 원래 CWE의 재스캔
- 공격자 제어 데이터가 sink 구조를 바꿀 수 있는지 확인
- 새 dependency/SCA 위험
- 인증·인가 우회
- 민감정보 로깅
- blacklist/부분 필터 우회
- 다른 호출 경로의 동종 취약점

## 자율성 게이트

| 동작 | 기본 | 필요 조건 |
| --- | --- | --- |
| scan | 허용 | 로컬 허가 경로 |
| patch candidate | 허용 | dry-run |
| project test | 비활성 | 명시적 `--execute-tests` |
| 원본 적용 (`run`) | 비활성 | VERIFIED + `--apply` |
| branch/commit/push | `publish` 호출 시 활성 | VERIFIED + clean tree + 기존 Git 인증 |
| PR | 비활성 | `--pull-request` + 별도 credential |
| DAST | 비활성 | authorized target |
| deploy | 비활성 | pushed commit gate + staging/canary/bounded observation/promotion/rollback + 승인 |

## 취약점 신고

하네스 자체에서 취약점을 발견하면 원격 대상에 악용하지 말고 재현 가능한 최소 테스트와 함께
비공개 채널로 보고합니다.
