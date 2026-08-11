# Tool Registry

기계 판독 설정은 `config/tools.yaml`에 있습니다.

## 등록 필드

| 필드 | 의미 |
| --- | --- |
| name | 고유 도구 이름 |
| category | sast/sca/secret/dast/test/scm/sandbox |
| command | shell 문자열이 아닌 argv template |
| parser | semgrep-json, sarif, trivy-json 등 |
| timeout | 단계별 최대 실행 시간 |
| required | 실패 시 전체 run을 중단할지 |
| network | 네트워크 필요 여부 |
| authorization_required | DAST 등 추가 허가 필요 여부 |

## 실행 규칙

- 설치되지 않은 optional 도구는 SKIPPED입니다.
- required 도구가 없거나 실패하면 FAILED입니다.
- parser 오류는 “Finding 없음”이 아닙니다.
- 도구 출력은 원문 artifact와 정규화 결과를 분리합니다.
- 도구 버전을 evidence에 기록합니다.
- 경로와 config는 target root 밖으로 escape할 수 없습니다.

## 정규화

모든 scanner는 최소 다음 필드로 변환됩니다.

```json
{
  "finding_id": "VULN-...",
  "type": "SQL Injection",
  "cwe": "CWE-89",
  "severity": "HIGH",
  "file": "app.py",
  "line": 10,
  "function": "get_user",
  "source": "request.args.get",
  "sink": "cursor.execute",
  "scanner": "builtin-python",
  "rule_id": "autopatch.python.formatted-sql-query"
}
```

원시 도구에 없는 필드는 추측하지 않고 `null`로 둡니다.
