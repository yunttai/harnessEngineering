# ADR-0005: Isolated Differential Verification

- 상태: ACCEPTED
- 결정일: 2026-08-12

## 결정

동적 검증은 설정과 CLI의 독립 DAST 게이트를 통과한 경우에만 실행합니다. Docker verifier는
원본을 `/source`에 read-only로, 임시 패치 사본을 `/workspace`에 writable로 마운트하고 다음
경계를 강제합니다.

- read-only container root filesystem
- `CAP_DROP=ALL`과 `no-new-privileges`
- CPU, memory, PID, timeout 제한
- build/test 기본 network `none`
- container image 자동 pull 기본 금지(`allow_image_pull: false`)
- 애플리케이션 DAST 시 host publish가 없는 Docker internal network
- 같은 internal network의 일회용 probe/scanner container만 애플리케이션에 접근
- readiness 성공 후에만 ZAP/Nuclei 실행
- 모든 container/network/temp workspace의 `finally` cleanup

`autopatch-security-tests.yaml`은 Pydantic `SecurityTestManifest`로 파싱합니다. 명령 테스트는
baseline/patched exit code를, DAST 테스트는 baseline 최소 Finding과 patched 최대 Finding을
명시하여 동일 후보의 전후 차이를 evidence로 남깁니다.

## 실패 정책

- Docker/DAST 도구 미설치, readiness timeout, parser 오류는 PASS가 아닙니다.
- 외부 DAST는 설정의 exact authorized target만 허용합니다.
- 생성된 sandbox-internal target은 `allow_sandbox_loopback`과 DAST autonomy가 모두 켜져야 합니다.
- Docker가 선택되었는데 daemon/명령 실행이 실패하면 local-copy로 자동 fallback하지 않습니다.
