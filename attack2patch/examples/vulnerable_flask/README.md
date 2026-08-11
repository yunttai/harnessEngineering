# Vulnerable Python SQL Example

교육·하네스 자체 테스트용 로컬 예제입니다.

취약 코드:

```python
query = f"SELECT * FROM users WHERE id={user_id}"
cursor.execute(query)
```

실행:

```bash
autopatch scan examples/vulnerable_flask
autopatch run examples/vulnerable_flask --execute-tests --execute-security-tests
```

원본을 직접 수정하지 않는 데모:

```bash
bash scripts/demo.sh
```

`security_test.py`는 패치 전에는 실패하고 parameterized query 적용 후 통과합니다.

`autopatch-security-tests.yaml`은 CWE-89 보안 재현 테스트를 선언하며, 명시적으로
`--execute-security-tests`를 사용한 경우에만 격리 복사본에서 실행됩니다.
