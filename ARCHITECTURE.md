# ARCHITECTURE.md

Attack2Patch의 최상위 아키텍처 맵입니다. 세부 결정은
`docs/design-docs/`, 요구사항은 `docs/product-specs/`, 진행 상태는 `docs/exec-plans/`에
기록합니다.

## 1. 제품 파이프라인

```text
Source Repository
      │
      ▼
Detection Harness
  ├─ SAST
  ├─ SCA
  ├─ Secret
  └─ DAST (authorized only)
      │
      ▼
Finding Normalizer
      │
      ▼
Analysis Harness
  ├─ source/sink
  ├─ data flow
  ├─ validation/auth context
  └─ root cause
      │
      ▼
Patch Harness
  ├─ candidate A
  ├─ candidate B
  └─ candidate C
      │
      ▼
Verification Harness
  ├─ build/type/lint
  ├─ regression
  ├─ security re-scan
  └─ exploit mitigation
      │
      ├─ FAIL → feedback → Patch Harness
      └─ PASS
           │
           ▼
Review Gate → Git Branch/PR → Staging/Canary → Production
```

운영 배포는 MVP의 자동 기본 동작이 아닙니다. 검증된 패치를 브랜치/PR로 전달하는 수준을
초기 완료 기준으로 둡니다.

## 2. 코드 레이어

각 레이어는 자신보다 오른쪽에 있는 레이어를 import하지 않습니다.

```text
Types → Config → Repo → Service → Runtime → UI
          ↑
       Providers
```

| 레이어 | 책임 | 허용되는 주요 의존성 |
| --- | --- | --- |
| Types | Finding, Analysis, Patch, Verification, Run 스키마 | 표준 라이브러리, Pydantic |
| Config | YAML/env 설정 파싱과 정책 검증 | Types |
| Providers | Scanner/Patcher/Verifier/Publisher Protocol | Types |
| Repo | 실행 evidence와 상태 저장 | Types, Config |
| Service | 정규화, 분석, 선택, 오케스트레이션 | Types, Config, Repo, Providers |
| Runtime | CLI 프로세스, AST, sandbox, Git 어댑터 | 하위 레이어 |
| UI | Typer/FastAPI 조립 및 사용자 경계 | 모든 하위 레이어 |

`Providers`는 인증, 외부 도구, LLM, GitHub, sandbox 같은 교차 관심사의 명시적 인터페이스입니다.
Service는 Runtime 구현을 직접 생성하지 않고 Protocol을 통해 주입받습니다.

## 3. 핵심 도메인 객체

```text
Finding
├── identity/fingerprint
├── CWE/severity/location
├── source/sink
├── scanner
└── evidence

AnalysisResult
├── root_cause
├── exploitability
├── confidence
├── recommended_fix
└── code_context

PatchCandidate
├── TextEdit[]
├── unified_diff
├── rationale
└── expected_security_effect

VerificationReport
├── build
├── functional
├── security_rescan
├── exploit
├── score
└── eligible

RunReport
├── state transitions
├── findings
├── outcomes
└── artifact paths
```

## 4. 상태 머신

```text
CREATED
  ↓
DETECTING
  ↓
DETECTED
  ↓
ANALYZING
  ↓
PATCH_GENERATING
  ↓
VERIFYING
  ├─ FAILED
  ├─ NEEDS_HUMAN_REVIEW
  └─ VERIFIED
        ↓
      APPLIED
        ↓
      PR_CREATED
        ↓
      DEPLOYED
```

모든 전이는 timestamp와 evidence를 남깁니다. 실패 상태를 덮어쓰지 않고 다음 시도에 입력으로
사용합니다.

## 5. 검증 불변 조건

1. 원본 파일은 dry-run 동안 변경하지 않습니다.
2. 후보 검증은 임시 복사본에서 수행합니다.
3. 원본 SHA-256이 후보 생성 시점과 다르면 적용을 중단합니다.
4. build 실패 후보는 선택할 수 없습니다.
5. security re-scan에서 동일 fingerprint/CWE-location이 남으면 선택할 수 없습니다.
6. regression 실패 후보는 선택할 수 없습니다.
7. exploit 검증이 가능한데 실패하면 선택할 수 없습니다.
8. 검증이 SKIPPED인 항목은 보고서에 명시하며 신뢰도를 낮춥니다.
9. 패치 적용, Git, PR, 배포는 독립된 자율성 게이트입니다.
10. 공격 재현/DAST는 허가된 대상과 명시된 정책에서만 수행합니다.

## 6. 패치 점수

계획서의 평가 모델을 그대로 사용합니다.

| 항목 | 배점 |
| --- | ---: |
| Security Test | 40 |
| Regression Test | 30 |
| Code Change Size | 15 |
| Build Stability | 10 |
| Coding Style | 5 |
| 합계 | 100 |

점수는 순위 결정용이며 필수 게이트를 대체하지 않습니다. 예를 들어 build가 실패한 후보는
총점과 관계없이 탈락합니다.

## 7. 저장 구조

```text
.autopatch/runs/<run-id>/
├── run.json
├── findings.json
├── events.jsonl
└── finding-<finding-id>/
    ├── analysis.json
    ├── candidates.json
    ├── evaluations.json
    └── selected.diff
```

전체 환경 변수는 evidence에 저장하지 않으며, 설정된 정규식과 고신뢰 토큰 패턴은 artifact
기록 직전에 best-effort redaction합니다. 원시 외부 도구 로그 자체를 장기 보존하는 기능은 MVP에서
비활성입니다.

## 8. 확장 지점

- Scanner Provider: Semgrep, CodeQL, Trivy, Grype, OSV, Gitleaks, ZAP, Nuclei
- Analysis Provider: AST/data-flow, CodeQL graph, LLM structured output
- Patch Provider: AST rewrite, framework codemod, LLM candidate generation
- Verification Provider: Docker/VM sandbox, application harness, exploit replay
- Publisher Provider: GitHub App branch/commit/PR
- Deployment Provider: staging, canary, rollback, post-deploy observation
