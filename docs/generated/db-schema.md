# SQLite 데이터베이스 스키마

`SQLiteRepository`가 시작 시 다음 테이블을 `CREATE TABLE IF NOT EXISTS`로 생성한다. 도메인
객체의 전체 strict JSON을 `data`에 저장하고 조회·정렬·참조에 필요한 열은 별도로 유지한다.

| 테이블 | 주요 열 | 관계/용도 |
| --- | --- | --- |
| `attack_events` | `id`, `detected_at`, `status`, `data` | 공격 event 원본 |
| `code_findings` | `id`, `event_id`, `data` | event FK, 파일·함수·line·rule |
| `patch_candidates` | `id`, `finding_id`, `status`, `data` | finding FK, Diff·hash·검증 결과 |
| `deployments` | `id`, `patch_id`, `status`, `deployed_at`, `data` | patch FK, 이전/후보 image와 검증 |
| `state_transitions` | `sequence`, `entity_type`, `entity_id`, `event_id`, `occurred_at`, `status`, `error` | append-only 처리 이력 |

SQLite foreign key enforcement를 connection별로 활성화한다. UUID는 canonical text, 시간은 timezone을
포함한 ISO-8601, evidence/검증 세부는 Pydantic JSON으로 저장한다. patch workspace 경로와 image
tag는 외부 입력이 아니라 서버가 생성한 값만 저장한다.
