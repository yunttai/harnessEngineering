# 생성 산출물

이 디렉터리는 코드에서 생성된 사람이 읽는 문서를 보관합니다.

- `finding-schema.md`
- `run-report-schema.md`

재생성:

```bash
cd attack2patch
PYTHONPATH=src python scripts/generate-schemas.py
```

JSON Schema 원본은 `attack2patch/schemas/`에 저장됩니다.
