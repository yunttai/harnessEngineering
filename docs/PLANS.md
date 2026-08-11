# PLANS.md — 실행 계획 규약

큰 변경은 `exec-plans/active/<slug>.md`에 기록합니다.

## 필수 머리말

```markdown
# 실행 계획: 제목

- 상태: IN_PROGRESS | BLOCKED | DONE
- 생성일: YYYY-MM-DD
- 소유자: agent/person
- 완료 기준:
```

## 필수 섹션

- 배경
- 범위와 비범위
- 단계별 체크리스트
- 검증 명령
- 위험과 rollback
- 진행 로그
- 결정 기록
- 남은 기술 부채

## 규칙

- 완료 기준은 실행 가능한 명령이나 명확한 artifact로 판정합니다.
- 진행 중 발견한 범위 변경을 조용히 반영하지 말고 계획에 기록합니다.
- 완료되면 `completed/`로 이동합니다.
- 알려진 부채는 `tech-debt-tracker.md`에 연결합니다.
- 패치 연구 실험은 대상 commit, Finding, 후보, 검증 결과를 남깁니다.
