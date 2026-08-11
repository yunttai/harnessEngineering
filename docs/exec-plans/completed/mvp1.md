# 실행 계획: MVP 1 — 탐지·분석·패치·정적 검증

- 상태: DONE
- 생성일: 2026-08-11
- 소유자: orchestrator
- 완료 기준: 예제 CWE-89에 대해 scan→analysis→candidate→sandbox verification→diff가 재현되고
  `bash scripts/check.sh`가 통과한다.

## 범위

- Python, CWE-89, 내장 AST scanner와 optional Semgrep
- 파일 evidence, build/re-scan/구조적 exploit mitigation, opt-in pytest

## 비범위

- GitHub 원격 PR, Docker security boundary, production deploy
- 일반 interprocedural data flow, 복잡 ORM 자동 패치

## 단계

- [x] 저장소 맵과 Agent 팀
- [x] 공통 schema와 설정/tool registry
- [x] 내장 scanner와 CWE-89 patch generator
- [x] sandbox verifier와 score/selection
- [x] CLI/API, 예제, 테스트, CI와 문서 검증

## 검증 명령

```bash
bash scripts/check.sh
bash attack2patch/scripts/demo.sh
```

## 위험과 rollback

로컬 복사 sandbox는 악성 대상 코드에 대한 보안 경계가 아니다. 프로젝트 테스트는 기본 off로
유지하고 Docker/VM 격리 공급자 도입 전에는 신뢰된 대상만 실행한다. 회귀 시 MVP 1 변경 commit을
revert하고 evidence를 보존한다.

## 진행 로그

- 2026-08-11: 레포 구조, 실행 가능한 Python MVP와 예제 구성
- 2026-08-11: 하네스 검증 통과 후 DONE 처리

## 결정 기록

- 실제 build/test/re-scan/exploit evidence만 VERIFIED 판정에 사용한다.

## 남은 기술 부채

- `../tech-debt-tracker.md`의 TD-001, TD-002를 따른다.
