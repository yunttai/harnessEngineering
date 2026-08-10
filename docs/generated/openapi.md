# Attack2Patch API 명세

- Base URL: `http://127.0.0.1:8080`
- Content type: `application/json`
- 외부 request object는 알 수 없는 필드를 거부한다.

| Method | Path | Body | 성공 | 설명 |
| --- | --- | --- | --- | --- |
| GET | `/health` | 없음 | 200 | 제품 health |
| POST | `/api/logs` | `HttpLogRecord` | 201/202 | 공격 탐지 시 event 생성, 정상 요청은 저장하지 않음 |
| GET | `/api/events` | 없음 | 200 | 최신순 event 목록 |
| GET | `/api/events/{event_id}` | 없음 | 200 | finding, patch, deployment, 전이 이력 포함 상세 |
| POST | `/api/events/{event_id}/patches` | `{}` | 201 | 원본을 변경하지 않고 Diff 생성 |
| POST | `/api/patches/{patch_id}/approve` | `{"approved": true}` | 200 | 격리 workspace에 patch 적용 |
| POST | `/api/patches/{patch_id}/reject` | `{"approved": true}` | 200 | 생성된 patch 거절 |
| POST | `/api/patches/{patch_id}/validate` | `{}` | 200/422 | 5개 필수 검증 실행 |
| POST | `/api/patches/{patch_id}/deploy` | `{"approved": true}` | 201/422 | build, Compose 배포, 사후 검증, 필요 시 rollback |
| POST | `/api/deployments/{deployment_id}/rollback` | `{"approved": true}` | 200 | 완료 배포를 이전 image로 수동 복구 |

## HttpLogRecord

```json
{
  "timestamp": "2026-08-10T10:01:00Z",
  "method": "GET",
  "path": "/api/users",
  "parameters": {"name": "' OR 1=1--"},
  "source_ip": "127.0.0.1",
  "status_code": 200,
  "headers": {}
}
```

`method`는 `GET|POST|PUT|PATCH|DELETE`, status는 `100..599`, timestamp는 timezone 필수다.
오류는 `{"error": "<code>", "details": ...}`이며 schema 오류 400, 미존재 404, 승인 누락 403,
상태 전이 위반 409, 검증/배포 실패 422를 사용한다.
