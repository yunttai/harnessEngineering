# 실행 계획: MVP 3 — 동적·격리 검증

- 상태: DONE
- 생성일: 2026-08-11
- 소유자: orchestrator
- 완료 기준: 네트워크가 제한된 컨테이너에서 애플리케이션과 보안 테스트를 실행하고,
  패치 전후 exploit 결과를 비교할 수 있다.

## 단계

- [x] Docker sandbox provider
- [x] read-only source + writable overlay
- [x] CPU/memory/pid/time limit
- [x] default network none
- [x] application readiness probe
- [x] exploit test manifest schema
- [x] ZAP/Nuclei authorized adapter
- [x] before/after differential oracle
- [x] artifact cleanup

## 구현 evidence

- Docker command/network/readiness/cleanup과 DAST differential 계약 테스트
- strict manifest JSON Schema 생성
- staging→canary→rollback deployment service와 CLI 연결
- 2026-08-12: 57 tests passed, `bash scripts/check.sh` 통과
- 실제 Docker에서 `/source` 쓰기 차단, `/workspace` 쓰기 성공
- host publish 없는 internal network readiness와 종료 후 container/network 0건
- Python digest `229a2c5b…d36`에서 실제 Docker verifier build/re-scan/exploit 검증 통과
- Nuclei digest `582d5546…32eb`에서 custom template baseline 1건 → patched 0건
- ZAP digest `781a2bda…1ef`에서 JSON report 6건 파싱

실검증 image digest는 각각 Python `229a2c5b…d36`, Nuclei `582d5546…32eb`, ZAP
`781a2bda…1ef`입니다. 코드 경로는 image/daemon이 없거나 응답하지 않으면 fail-closed이며
local-copy로 자동 fallback하지 않습니다. 다중 OS/architecture와 고정 digest CI matrix는
TD-013에서 추적합니다.

## 주요 위험

- container escape와 Docker socket 권한
- 테스트가 외부 서비스에 의존
- 비결정적 exploit oracle
- 서비스 secret 주입
