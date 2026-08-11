# ADR-0004: Layered Provider Architecture

- 상태: ACCEPTED
- 결정일: 2026-08-11

## 결정

```text
Types → Config → Repo → Service → Runtime → UI
```

외부 scanner, LLM, sandbox, GitHub, deploy는 Provider Protocol을 통해 주입합니다.

## 이유

- 순수 오케스트레이션 테스트 가능
- vendor/도구 교체 가능
- subprocess와 비즈니스 판정 분리
- 낮은 레이어의 UI/framework 결합 방지

## 기계적 검증

`attack2patch/scripts/check-architecture.py`가 `attack2patch/src/autopatch` import를 AST로
검사합니다.
