# 스펙: Patch Lifecycle

- 상태: IMPLEMENTED_FOR_CWE_89
- 소유: Service, Runtime

## 흐름

```text
Finding → AnalysisResult → PatchCandidate[]
→ VerificationReport[] → CandidateEvaluation[] → Selected Candidate
```

## 수용 기준

- [x] 후보가 original SHA를 포함
- [x] TextEdit 범위가 겹치지 않음
- [x] unified diff 생성
- [x] 원본은 dry-run에서 불변
- [x] 임시 복사본 검증
- [x] 필수 게이트와 점수 분리
- [x] apply 시 hash 재검증
- [x] 지원 불가 패턴은 사람 검토

## 후보 선택

1. 필수 게이트를 통과한 후보만 eligible
2. score 내림차순
3. 동점이면 changed lines가 작은 후보
4. 그래도 동점이면 candidate_id 안정 순서
