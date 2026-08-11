from __future__ import annotations

from pathlib import Path

from autopatch.types import AnalysisResult, CodeContext, Exploitability, Finding


CWE_GUIDANCE: dict[str, dict[str, object]] = {
    "CWE-89": {
        "root": "공격자 제어 값이 SQL 문자열 구조에 직접 삽입되어 query 문법을 변경할 수 있음",
        "fix": "DB driver의 parameterized query를 사용해 SQL 구조와 값을 분리",
        "forbidden": [
            "입력 문자열에서 따옴표나 SQL 키워드만 제거",
            "scanner ignore/noqa 추가",
            "오류를 삼켜 취약 동작을 숨김",
        ],
        "tests": [
            "정상 식별자 조회 회귀 테스트",
            "boolean-based SQL injection payload가 query 문자열에 포함되지 않는지 확인",
            "payload가 parameter tuple/dict로 전달되는지 확인",
        ],
    },
    "CWE-78": {
        "root": "공격자 제어 값이 shell command 문자열에 포함됨",
        "fix": "shell을 사용하지 않고 고정 executable과 argv list로 실행",
        "forbidden": ["문자 몇 개만 blacklist", "shell=True 유지"],
        "tests": ["metacharacter payload가 별도 argv 값으로 처리되는지 확인"],
    },
    "CWE-502": {
        "root": "신뢰할 수 없는 입력이 객체 역직렬화 과정에서 코드/객체 생성을 제어할 수 있음",
        "fix": "안전한 데이터 포맷과 명시적 schema로 교체",
        "forbidden": ["pickle 입력에 단순 서명만 추가하고 객체 생성을 계속 허용"],
        "tests": ["악성 object payload가 역직렬화되지 않는지 확인"],
    },
    "CWE-798": {
        "root": "자격증명 또는 secret이 소스 코드에 고정되어 배포·로그·저장소를 통해 노출될 수 있음",
        "fix": "secret manager 또는 환경 변수로 이동하고 노출된 secret을 회전",
        "forbidden": ["base64 인코딩만 적용"],
        "tests": ["저장소와 build artifact에 secret pattern이 없는지 확인"],
    },
}


class RuleBasedAnalyzer:
    name = "rule-based-analysis"

    def __init__(self, context_lines: int = 6) -> None:
        self.context_lines = context_lines

    def analyze(self, target: Path, finding: Finding) -> AnalysisResult:
        file_path = (target / finding.file).resolve()
        file_path.relative_to(target.resolve())
        lines = file_path.read_text(encoding="utf-8").splitlines()
        start = max(1, finding.line - self.context_lines)
        end = min(len(lines), (finding.end_line or finding.line) + self.context_lines)
        snippet = "\n".join(
            f"{index:>5}: {lines[index - 1]}" for index in range(start, end + 1)
        )

        guidance = CWE_GUIDANCE.get(
            finding.cwe,
            {
                "root": finding.message,
                "fix": "공격자 제어 입력과 위험 sink 사이의 신뢰 경계를 제거하거나 안전 API로 교체",
                "forbidden": ["scanner 결과만 숨기는 변경"],
                "tests": ["원래 취약 동작의 재현 테스트"],
            },
        )

        if finding.source and finding.sink:
            exploitability = Exploitability.LIKELY
            confidence = 0.85
        elif finding.sink:
            exploitability = Exploitability.UNCERTAIN
            confidence = 0.6
        else:
            exploitability = Exploitability.UNCERTAIN
            confidence = 0.45

        notes: list[str] = []
        validation = finding.metadata.get("existing_validation", [])
        if not isinstance(validation, list):
            validation = []
        if validation:
            notes.append("기존 validation이 실제 sink 이전에 적용되는지 별도 확인 필요")

        return AnalysisResult(
            finding_id=finding.finding_id,
            cwe=finding.cwe,
            root_cause=str(guidance["root"]),
            exploitability=exploitability,
            confidence=confidence,
            source=finding.source,
            sink=finding.sink,
            existing_validation=[str(item) for item in validation],
            recommended_fix=str(guidance["fix"]),
            forbidden_fixes=[str(item) for item in guidance["forbidden"]],
            required_tests=[str(item) for item in guidance["tests"]],
            context=CodeContext(
                file=finding.file,
                start_line=start,
                end_line=end,
                snippet=snippet,
                function=finding.function,
            ),
            notes=notes,
        )
