# ADR-0006: Production Observation and Credential Smoke

- 상태: ACCEPTED
- 결정일: 2026-08-12

## 결정

- Python, Nuclei, ZAP은 amd64/arm64 manifest를 포함하는 `@sha256` reference로 고정한다.
- GitHub Actions는 `ubuntu-24.04` amd64와 `ubuntu-24.04-arm` arm64에서 동일 Docker smoke를
  실행한다. ARM GitHub-hosted runner는 public preview이므로 실행 실패를 기능 성공으로 숨기지 않는다.
- GitHub App smoke는 App JWT의 repository installation ID, installation token의 최소 권한,
  exact repository GET만 검사하며 branch나 PR을 만들지 않는다.
- canary 이후 observation command를 정해진 interval/window/max attempts 안에서 반복한다. 첫
  non-PASS, timeout 또는 한도 소진은 rollback을 호출하고 `DEPLOY_FAILED` evidence를 남긴다.

## 패처 경계

결정적 확장은 다음 AST shape에만 적용한다.

- CWE-78: 고정 executable과 option, standalone formatted value로만 구성된 subprocess f-string
- CWE-502: `yaml.load`의 명시 unsafe loader 또는 `yaml.unsafe_load`
- CWE-22: 신뢰 root의 `flask.send_file(os.path.join(root, user_path))`

동적 값이 고정 argv와 결합되거나 path root도 공격자 제어인 경우 후보를 생성하지 않는다.
pickle은 안전 포맷 migration과 호환성 계획 없이는 자동 변환하지 않는다.
