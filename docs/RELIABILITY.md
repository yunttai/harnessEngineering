# RELIABILITY.md — 안정성 기준

## 재현성

- Run ID, 대상 절대 경로, 파일 hash, config snapshot, scanner 버전, 명령, exit code를 기록합니다.
- 후보는 `TextEdit[]`와 unified diff를 함께 보존합니다.
- 임시 sandbox 경로는 보고서에 영구 기준으로 사용하지 않습니다.
- 동일한 Finding fingerprint는 동일한 코드 상태에서 안정적으로 생성되어야 합니다.

## Timeout

| 단계 | 기본 |
| --- | ---: |
| scanner | 180초 |
| build | 120초 |
| regression | 300초 |
| exploit test | 60초 |

Timeout은 FAIL 또는 명시적 SKIPPED이며 PASS가 아닙니다.

## 실패 격리

- 한 scanner 실패가 다른 scanner 결과를 삭제하지 않습니다.
- required scanner 실패는 run을 실패시킵니다.
- optional scanner 실패는 degraded 상태로 기록합니다.
- 한 Finding의 패치 실패가 다른 Finding evidence를 손상시키지 않습니다.

## 멱등성

- scan은 원본을 수정하지 않습니다.
- dry-run `run`은 원본을 수정하지 않습니다.
- apply는 원본 hash가 후보 기준과 일치할 때만 한 번 적용합니다.
- 이미 적용된 편집을 다시 적용하지 않습니다.

## 상태 전이

허용되지 않은 역전이와 건너뛰기를 막습니다. 예를 들어 `PATCH_GENERATING`에서 실제 검증 없이
`VERIFIED`로 이동할 수 없습니다.

## 로그

- JSON 산출물과 사람이 읽는 요약을 함께 제공합니다.
- stdout/stderr excerpt를 제한해 artifact 폭증을 막습니다.
- 민감정보를 redact합니다.
- 실패 원인을 다음 Agent가 사용할 수 있는 필드로 저장합니다.

## 품질 목표

MVP 연구 지표:

- Detection Precision
- Patch Success Rate
- Security Fix Rate
- Regression Rate
- Exploit Mitigation Rate
- Autonomous Patch Rate
- 평균 후보 수와 평균 재시도 수
- 검증 단계별 SKIPPED 비율

정의는 `product-specs/PRD.md`와 원본 계획서에 맞춰 유지합니다.
