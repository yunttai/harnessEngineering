# 스펙: Finding Normalization

- 상태: IMPLEMENTED
- 소유: Types, Runtime, Service

## 목표

Semgrep, CodeQL, SCA, secret, DAST처럼 서로 다른 결과를 공통 모델로 변환합니다.

## 수용 기준

- [x] 필수 필드 validation
- [x] deterministic finding_id/fingerprint
- [x] severity enum
- [x] scanner/rule evidence
- [x] relative file path
- [x] duplicate merge
- [x] parser 오류와 zero finding 구분

## 정규화 원칙

원시 결과에 없는 source/sink/function을 추측하지 않습니다. 분석 단계가 채우는 정보와 scanner가
제공한 사실을 구분합니다.
