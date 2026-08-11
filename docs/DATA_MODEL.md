# 데이터 모델

## Finding

취약점 하나의 정규화된 사실과 scanner evidence입니다. `fingerprint`는 중복 제거와 재스캔
비교에 사용합니다.

## AnalysisResult

Finding 자체와 분리합니다. root cause, exploitability, confidence, code context, recommended fix,
required tests를 포함합니다.

## PatchCandidate

패치는 텍스트 설명만이 아니라 다음 기계 판독 정보를 가집니다.

- 기준 파일 SHA-256
- `TextEdit[]`
- unified diff
- changed lines
- expected security effect
- 적용 전제

## VerificationReport

각 단계는 `PASS`, `FAIL`, `SKIPPED`, `ERROR` 중 하나입니다. 명령, exit code, duration,
stdout/stderr excerpt를 보존합니다.

## CandidateEvaluation

VerificationReport와 100점 Patch Score, 필수 게이트 충족 여부, 탈락 이유를 결합합니다.

## RunReport

하나의 target 실행을 나타내며 state transition, FindingOutcome, 적용 여부, artifact 경로를
포함합니다.

## 저장

MVP는 파일 기반 저장소를 사용합니다. 향후 PostgreSQL로 교체할 때 `repo` 레이어 인터페이스를
유지하며 Finding, Patch, Verification, Execution Log, Evidence 테이블로 분리합니다.
