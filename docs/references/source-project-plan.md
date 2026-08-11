# Harness 기반 취약점 자동 탐지·패치·검증·배포 시스템 개발 계획서

## 1. 프로젝트 개요

### 1.1 프로젝트명

Harness 기반 Secure Auto-Patching System

### 1.2 프로젝트 목표

본 프로젝트의 목표는 애플리케이션에서 발견된 보안 취약점을 단순히 탐지하는 것에서 끝내지 않고,

탐지 → 취약 코드 분석 → 시큐어코딩 패치 생성 → 기능 및 보안 검증 → 배포

과정을 하나의 자동화된 Harness로 구성하는 것이다.

기존 보안 도구는 취약점의 위치와 위험도를 알려주는 데 집중되어 있으며, 실제 수정과 수정 결과 검증은 개발자가 직접 수행해야 하는 경우가 많다.

본 시스템에서는 여러 보안 도구와 LLM Agent를 하나의 실행 Harness로 연결하여 취약점 발견 이후의 대응 과정까지 자동화한다.

---

# 2. 개발 배경

일반적인 DevSecOps 환경에서는 다음과 같은 과정이 각각 독립적으로 수행된다.

1. SAST/DAST 도구를 이용한 취약점 탐지
2. 개발자의 취약 코드 분석
3. 코드 수정
4. 테스트 수행
5. 보안 도구를 이용한 재검사
6. Pull Request 생성
7. CI/CD를 통한 배포

이 과정에서는 취약점 보고서와 실제 코드 사이의 연결이 부족하고, 동일한 취약점에 대한 분석과 수정 작업이 반복적으로 발생한다.

특히 자동 취약점 탐지 도구가 결과를 생성하더라도 개발자가 다음 내용을 다시 판단해야 한다.

- 어떤 코드가 실제 원인인지
- 해당 취약점이 실제로 악용 가능한지
- 어떤 방식으로 수정해야 하는지
- 수정으로 인해 기존 기능이 깨지지 않았는지
- 취약점이 실제로 제거되었는지

본 프로젝트에서는 이러한 과정을 Harness 내부의 단계별 Agent와 검증기를 통해 자동화한다.

---

# 3. 전체 시스템 구조

전체 처리 흐름은 다음과 같다.

```
                ┌─────────────────┐
                │ Source Repository│
                └────────┬────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │ 1. Detection Harness │
              └──────────┬──────────┘
                         │
          SAST / SCA / Secret / DAST
                         │
                         ▼
              ┌─────────────────────┐
              │ Finding Normalizer   │
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │ 2. Analysis Harness  │
              └──────────┬──────────┘
                         │
              Root Cause Analysis
                         │
                         ▼
              ┌─────────────────────┐
              │ 3. Patch Harness     │
              └──────────┬──────────┘
                         │
                  Patch Candidate
                         │
                         ▼
              ┌─────────────────────┐
              │ 4. Verify Harness    │
              └──────────┬──────────┘
                         │
         Build / Test / Security Test
                         │
                  ┌──────┴──────┐
                  │             │
                FAIL           PASS
                  │             │
                  ▼             ▼
             Re-Patching     PR 생성
                                │
                                ▼
                      ┌──────────────────┐
                      │ 5. Deploy Harness│
                      └────────┬─────────┘
                               │
                         Canary/Staging
                               │
                               ▼
                           Production

```

---

# 4. 핵심 Harness 구성

## 4.1 Detection Harness

Detection Harness는 프로젝트의 취약점을 탐지하고 서로 다른 보안 도구의 결과를 하나의 형태로 정규화한다.

### 사용 가능한 탐지 방식

SAST

- Semgrep
- CodeQL
- Bandit
- SpotBugs
- ESLint Security Plugin

SCA

- Trivy
- Grype
- OSV-Scanner
- Dependency-Check

Secret Detection

- Gitleaks
- TruffleHog

DAST

- OWASP ZAP
- Nuclei

### 출력 데이터

각 도구에서 발생하는 결과를 다음 형태로 통합한다.

```
{
  "finding_id": "VULN-001",
  "type": "SQL Injection",
  "cwe": "CWE-89",
  "severity": "HIGH",
  "file": "src/user.py",
  "line": 42,
  "function": "get_user",
  "source": "request.args.get('id')",
  "sink": "cursor.execute",
  "scanner": "semgrep"
}

```

이 단계의 핵심은 단순히 Scanner를 실행하는 것이 아니라 여러 도구의 결과를 **공통 Finding Schema**로 변환하는 것이다.

---

# 5. 취약점 분석 Harness

탐지 결과가 실제 취약점인지 판단하고 취약점의 원인을 분석한다.

## 주요 분석 정보

Harness가 다음 데이터를 자동으로 수집한다.

```
취약 함수
↓
호출 함수
↓
입력 데이터
↓
Data Flow
↓
Dangerous Sink
↓
인증/인가 여부
↓
기존 Validation

```

예를 들어 다음 코드가 탐지되었다고 가정한다.

```
user_id = request.args.get("id")

query = f"SELECT * FROM users WHERE id={user_id}"

cursor.execute(query)

```

분석 Harness에서는 다음 결과를 생성한다.

```
CWE
CWE-89 SQL Injection

Source
request.args.get()

Sink
cursor.execute()

Root Cause
사용자 입력값이 SQL Query에 직접 삽입됨

Recommended Fix
Parameterized Query 사용

```

---

# 6. Patch Harness

Patch Harness는 분석 결과를 기반으로 실제 코드 수정안을 생성한다.

단순한 코드 생성이 아니라 다음 정보를 함께 사용한다.

```
Finding
+
Source Code
+
Call Context
+
Framework
+
Existing Coding Style
+
CWE Secure Coding Rule
+
Test Code

```

LLM Agent는 해당 정보를 기반으로 최소 수정 패치를 생성한다.

예:

기존 코드

```
query = f"SELECT * FROM users WHERE id={user_id}"
cursor.execute(query)

```

패치

```
cursor.execute(
    "SELECT * FROM users WHERE id = %s",
    (user_id,)
)

```

패치는 전체 파일을 다시 생성하지 않고 가능하면 Git diff 형태로 관리한다.

```
- query = f"SELECT * FROM users WHERE id={user_id}"
- cursor.execute(query)

+ cursor.execute(
+     "SELECT * FROM users WHERE id = %s",
+     (user_id,)
+ )

```

이를 통해 잘못된 대규모 코드 변경을 방지한다.

---

# 7. Patch Candidate 방식

하나의 패치만 생성하지 않고 여러 개의 Patch Candidate를 생성할 수도 있다.

예:

```
Patch Candidate A
Parameterized Query

Patch Candidate B
ORM Query 변경

Patch Candidate C
Input Validation + Parameterized Query

```

각 패치를 자동으로 검증한 뒤 가장 높은 평가를 받은 패치를 선택한다.

```
Patch Score

Security Test       40
Regression Test     30
Code Change Size    15
Build Stability     10
Coding Style         5

Total              100

```

예:

```
Candidate A : 94
Candidate B : 82
Candidate C : 76

→ Candidate A 선택

```

---

# 8. Verification Harness

자동 패치 시스템에서 가장 중요한 부분이다.

LLM이 코드를 수정했다는 사실만으로 취약점이 해결되었다고 판단하지 않는다.

다음 검증을 순차적으로 수행한다.

## Stage 1. Build Verification

```
Compile
Dependency Install
Lint
Type Check

```

실패 시 패치를 폐기하고 Patch Harness로 다시 전달한다.

---

## Stage 2. Functional Test

기존 테스트 코드를 실행한다.

```
Unit Test
Integration Test
API Test

```

목적은 패치로 인해 기존 기능이 손상되지 않았는지 확인하는 것이다.

---

## Stage 3. Security Re-Scan

취약점을 발견했던 Scanner를 다시 실행한다.

예:

```
Before

CWE-89
src/user.py:42
HIGH

After

Finding 없음

```

---

## Stage 4. Exploit Verification

가능한 경우 탐지된 취약점에 대해 재현용 요청 또는 테스트를 생성한다.

예:

SQL Injection

```
?id=1 OR 1=1

```

패치 전

```
HTTP 200
전체 사용자 데이터 반환

```

패치 후

```
HTTP 400

또는

정상적인 단일 사용자 검색

```

즉 단순 Scanner 결과가 사라지는 것뿐만 아니라 **실제 취약 동작이 제거되었는지 확인한다.**

---

# 9. Patch Verification Loop

검증 실패 시 Harness가 결과를 다시 Patch Agent에게 전달한다.

```
Patch 생성
   │
   ▼
Build
   │
   ├─ FAIL ───────────────┐
   │                      │
   ▼                      │
Unit Test                 │
   │                      │
   ├─ FAIL ───────────────┤
   │                      │
   ▼                      │
Security Test             │
   │                      │
   ├─ FAIL ───────────────┤
   │                      │
   ▼                      │
Exploit Test              │
   │                      │
   ├─ FAIL ───────────────┤
   │                      │
   ▼                      │
 PASS                     │
   │                      │
   ▼                      │
 PR 생성                  │
                          │
                          ▼
                    Patch Agent

```

실패 결과도 구체적으로 전달한다.

```
{
  "status": "PATCH_FAILED",

  "build": "PASS",

  "unit_test": {
    "status": "FAIL",
    "failed_test": "test_get_user"
  },

  "security_scan": {
    "status": "PASS"
  }
}

```

Agent는 이를 이용하여 수정된 패치를 다시 생성한다.

---

# 10. Deployment Harness

검증된 패치가 바로 운영 환경으로 배포되지 않도록 단계별 배포를 수행한다.

```
Patch
 ↓
Git Branch
 ↓
Pull Request
 ↓
CI
 ↓
Staging
 ↓
Security Test
 ↓
Canary Deployment
 ↓
Production

```

초기 개발 단계에서는 Production 자동 배포보다 다음 수준까지 구현하는 것이 적절하다.

```
Verified Patch
→ Branch 생성
→ Commit
→ Pull Request 생성
→ CI 결과 첨부

```

예:

```
fix/security-cwe89-user-query

```

PR 내용

```
Security Auto Patch

Vulnerability
CWE-89 SQL Injection

Location
src/user.py:42

Detection
Semgrep

Patch
Parameterized Query 적용

Verification

Build PASS
Unit Test 37/37 PASS
Semgrep PASS
Exploit Test PASS

Risk
LOW

```

---

# 11. Harness Orchestrator

전체 시스템은 중앙 Orchestrator가 관리한다.

```
              Orchestrator

      ┌──────────┼──────────┐
      ▼          ▼          ▼

 Detection    Analysis     Patch
   Agent       Agent       Agent

      │          │          │
      └──────────┼──────────┘
                 ▼

           Verification
              Agent
                 │
                 ▼
              Deploy
              Agent

```

각 Agent는 직접 모든 작업을 수행하지 않고 필요한 Tool을 호출한다.

예:

Detection Agent

```
semgrep
codeql
trivy
gitleaks

```

Patch Agent

```
Git
AST Parser
LLM
Secure Coding DB

```

Verification Agent

```
pytest
npm test
mvn test
semgrep
zap
nuclei

```

Deploy Agent

```
GitHub
GitHub Actions
Docker
Kubernetes

```

---

# 12. Tool Registry

Harness에서 Agent가 사용할 수 있는 Tool을 Registry 방식으로 관리한다.

```
tools:

  semgrep:
    category: sast
    command: semgrep scan

  trivy:
    category: sca
    command: trivy fs .

  pytest:
    category: test
    command: pytest

  docker:
    category: runtime

  github:
    category: scm

```

Agent는 필요한 도구를 선택하여 실행한다.

---

# 13. Evidence 기반 판단

시스템의 중요한 특징 중 하나는 모든 판단에 Evidence를 남기는 것이다.

예:

```
{
  "vulnerability": "CWE-89",

  "evidence": {
    "scanner": "semgrep",
    "rule": "python.lang.security.audit.formatted-sql-query",

    "source": "request.args.get",

    "sink": "cursor.execute",

    "file": "src/user.py",

    "line": 42
  }
}

```

패치 이후에도 동일하게 기록한다.

```
{
  "verification": {

    "build": "PASS",

    "unit_test": "37/37",

    "security_scan": "PASS",

    "exploit_test": "PASS"
  }
}

```

이를 통해 최종적으로

```
왜 취약하다고 판단했는가

↓

어떤 코드를 수정했는가

↓

왜 이 패치를 선택했는가

↓

취약점이 실제로 제거되었는가

```

를 추적할 수 있다.

---

# 14. 주요 대상 취약점

초기 버전에서는 자동 수정 가능성이 높은 취약점부터 지원한다.

1차 대상

```
CWE-89  SQL Injection
CWE-79  Cross Site Scripting
CWE-22  Path Traversal
CWE-78  Command Injection
CWE-502 Unsafe Deserialization
Hardcoded Secret
Weak Cryptography
Insecure Dependency

```

2차 대상

```
SSRF
Open Redirect
Missing Authentication
Broken Access Control
IDOR
Race Condition
Business Logic Vulnerability

```

특히 인증/인가나 Business Logic 관련 취약점은 단순 코드 패턴만으로 수정하기 어렵기 때문에 이후 단계에서 Context 분석 기능을 추가한다.

---

# 15. 기술 스택

Backend

```
Python
FastAPI
Pydantic
Celery 또는 자체 Task Runner

```

LLM / Agent

```
OpenAI API
Structured Output
Tool Calling

```

Code Analysis

```
Tree-sitter
Semgrep
CodeQL
AST Parser

```

Security

```
Semgrep
CodeQL
Trivy
OSV-Scanner
Gitleaks
OWASP ZAP
Nuclei

```

Test

```
pytest
JUnit
Jest
Playwright

```

Infrastructure

```
Docker
Docker Compose
Kubernetes

```

SCM / CI

```
Git
GitHub
GitHub Actions

```

Storage

```
PostgreSQL

Finding
Patch
Verification
Execution Log
Evidence

```

---

# 16. 데이터 구조

하나의 취약점을 다음 객체로 관리한다.

```
Finding

finding_id
repository
commit

cwe
severity

file
function
line

source
sink

scanner

analysis

patch_candidates[]

verification

deployment

status

```

상태는 다음과 같이 관리할 수 있다.

```
DETECTED

↓

ANALYZING

↓

PATCH_GENERATING

↓

PATCH_CREATED

↓

VERIFYING

↓

VERIFIED

↓

PR_CREATED

↓

DEPLOYED

```

실패 상태

```
ANALYSIS_FAILED
PATCH_FAILED
BUILD_FAILED
TEST_FAILED
SECURITY_TEST_FAILED
DEPLOY_FAILED

```

---

# 17. MVP 개발 범위

처음부터 모든 기능을 구현하기보다는 다음 형태로 MVP를 구성한다.

## MVP 1

```
Git Repository
      ↓
Semgrep
      ↓
Finding Parser
      ↓
LLM Analysis
      ↓
Patch 생성
      ↓
pytest
      ↓
Semgrep 재검사
      ↓
Git diff 출력

```

목표

```
취약점 탐지

→ 자동 수정

→ 테스트

→ 취약점 제거 확인

```

---

# 18. MVP 2

다음 기능을 추가한다.

```
Multi Scanner

Semgrep
Trivy
Gitleaks

```

그리고

```
Multiple Patch Candidate
Patch Ranking
Git Branch 생성
PR 자동 생성

```

까지 구현한다.

---

# 19. MVP 3

동적 검증 기능을 추가한다.

```
Docker Sandbox

↓

Application 실행

↓

DAST

↓

Exploit Verification

↓

Patch

↓

Application 재실행

↓

Exploit Re-Test

```

---

# 20. 최종 단계

최종적으로 다음 파이프라인을 구현한다.

```
Repository

↓

Security Scanning

↓

Finding Normalization

↓

Root Cause Analysis

↓

Patch Generation

↓

Patch Candidate Evaluation

↓

Build

↓

Regression Test

↓

Security Re-Scan

↓

Exploit Verification

↓

Pull Request

↓

CI/CD

↓

Staging

↓

Canary Deployment

↓

Production

```

---

# 21. 개발 일정

## 1주차

Harness Core 개발

```
Orchestrator
Tool Runner
Finding Schema
Execution Context
Logging

```

## 2주차

Detection Harness

```
Semgrep
Trivy
Gitleaks

Finding Normalizer

```

## 3주차

Patch Harness

```
Code Context Collector
LLM Patch Agent
Git Diff Generator
Secure Coding Rules

```

## 4주차

Verification Harness

```
Build
Unit Test
Regression Test
Security Re-Scan

```

## 5주차

Dynamic Verification

```
Docker Sandbox
Application Runner
DAST
Exploit Verification

```

## 6주차

GitHub Integration

```
Branch
Commit
PR
CI

```

## 7주차

Deployment Harness

```
Docker
Staging
Canary
Rollback

```

## 8주차

평가 및 고도화

```
Patch 성공률 측정
False Positive 분석
Patch Regression 분석
Demo Scenario 작성

```

---

# 22. 성능 평가 지표

단순히 “패치가 생성되었다”를 성공으로 판단하지 않는다.

### Detection Precision

실제 취약점 중 올바르게 탐지한 비율

### Patch Success Rate

```
검증을 통과한 패치
────────────────
전체 생성된 패치

```

### Security Fix Rate

패치 이후 취약점이 실제 제거된 비율

### Regression Rate

패치 이후 기존 테스트가 실패한 비율

### Exploit Mitigation Rate

실제 공격 재현이 패치 이후 차단된 비율

### Autonomous Patch Rate

사람의 수정 없이 최종 검증까지 완료한 비율

---

# 23. 실험 환경

취약점이 명확하게 존재하는 테스트 프로젝트를 사용한다.

예:

```
OWASP WebGoat
OWASP Juice Shop
DVWA
자체 Vulnerable Flask Application
자체 Vulnerable Spring Application

```

추가로 실제 CVE 패치 전후 코드를 활용한다.

```
Vulnerable Commit

↓

Auto Patch

↓

Official Security Patch와 비교

```

이를 통해 자동 생성 패치의 정확도를 평가할 수 있다.

---

# 24. 프로젝트 차별점

기존 취약점 분석 시스템

```
취약점 발견
      ↓
Report
      ↓
종료

```

본 프로젝트

```
취약점 발견

↓

Root Cause 분석

↓

Secure Coding Patch 생성

↓

Build/Test

↓

Security Re-Scan

↓

Exploit Verification

↓

Pull Request

↓

Deployment

```

즉 취약점을 알려주는 시스템이 아니라 **취약점 발견 이후 실제 수정과 검증까지 수행하는 보안 자동화 Harness**를 구축하는 것이 핵심이다.

---

# 25. 핵심 연구 주제

본 프로젝트에서 특히 연구 가치가 있는 부분은 다음 세 가지이다.

## 1. Finding-to-Code Context Reconstruction

Scanner가 제공하는 단편적인 취약점 정보를 이용하여

```
Source
→ Data Flow
→ Validation
→ Sink

```

구조를 자동으로 복원한다.

## 2. Patch Generation & Selection

하나의 패치를 생성하는 것이 아니라 여러 패치를 생성하고

```
Security
Functionality
Regression
Change Size

```

를 기준으로 가장 안정적인 패치를 자동 선택한다.

## 3. Verification-Driven Patching

LLM의 판단을 신뢰하는 것이 아니라 실제 실행 결과를 기준으로 패치를 평가한다.

```
LLM
"취약점을 수정했습니다."

X

Harness

Build PASS
37 Tests PASS
Security Scan PASS
Exploit Reproduction FAIL

→ FIX VERIFIED

```

이 구조를 통해 LLM은 패치 후보를 생성하는 역할을 하고, 최종 판단은 Harness의 실제 실행 결과가 담당하도록 구성한다.

---

# 26. 최종 목표

최종 시스템의 입력은 다음과 같이 단순화한다.

```
autopatch scan https://github.com/example/project

```

또는

```
autopatch run .

```

그러면 Harness가 자동으로

```
Repository 분석

→ 취약점 탐지

→ Root Cause 분석

→ 패치 생성

→ Build

→ Test

→ Security Verification

→ Exploit Verification

→ Git Branch 생성

→ Pull Request 생성

```

까지 수행한다.

최종적으로 개발자가 취약점 보고서를 받고 직접 원인을 찾고 수정하는 기존 방식에서 벗어나,

**취약점 탐지부터 시큐어코딩 패치, 검증 및 배포까지 하나의 폐쇄형 자동화 루프로 연결된 보안 Harness를 구축하는 것**을 프로젝트의 최종 목표로 한다.