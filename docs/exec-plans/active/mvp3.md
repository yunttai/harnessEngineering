# 실행 계획: MVP 3 — 동적·격리 검증

- 상태: IN_PROGRESS
- 생성일: 2026-08-11
- 소유자: orchestrator
- 완료 기준: 네트워크가 제한된 컨테이너에서 애플리케이션과 보안 테스트를 실행하고,
  패치 전후 exploit 결과를 비교할 수 있다.

## 단계

- [ ] Docker sandbox provider
- [ ] read-only source + writable overlay
- [ ] CPU/memory/pid/time limit
- [ ] default network none
- [ ] application readiness probe
- [ ] exploit test manifest schema
- [ ] ZAP/Nuclei authorized adapter
- [ ] before/after differential oracle
- [ ] artifact cleanup

## 주요 위험

- container escape와 Docker socket 권한
- 테스트가 외부 서비스에 의존
- 비결정적 exploit oracle
- 서비스 secret 주입
