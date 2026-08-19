# taut

Python 백엔드의 숨은 구조·실행 규칙을 명시하고, 확실히 증명되는 위반만 빠르게 막는 도구다.
같은 코드와 같은 설정에는 항상 같은 결과를 낸다. 특정 프로젝트의 이름이나 폴더 구조는
내장하지 않는다.

현재는 첫 공개 버전을 준비 중이다. 저장소에서 바로 사용하려면 다음처럼 설치한다.

```bash
uv add --dev "taut @ git+https://github.com/taewoo-dev/taut.git"
uv run taut check .
```

PyPI 공개 뒤에는 `uv add --dev taut`만으로 설치할 수 있다.

## 사용

프로젝트의 `pyproject.toml`에 역할과 허용 관계만 추가한다. `strict`의 기본값은 `true`이고,
파일 길이의 기본 상한은 700줄이다.

```toml
[tool.taut]
strict = true
source_roots = ["."]

[tool.taut.roles]
router = ["app/router/*.py", "app/router/**/*.py"]
service = ["app/service/*.py", "app/service/**/*.py"]

[tool.taut.allow]
router = ["router", "service"]
service = ["service"]

[tool.taut.zones]
test = ["tests/*.py", "tests/**/*.py"]

[tool.taut.transaction]
owner_roles = ["service"]
session_providers = ["app.database.get_async_session"]
```

외부 호출·DB·보안·DTO·Schema 규칙은 기본 제공되므로 저장소마다 다시 적지 않는다.
프로젝트가 기본과 다를 때만 작은 하위 설정을 추가한다.

여기서 `외부`는 소유 주체가 아니라 실행 경계를 뜻한다. 검사 대상 애플리케이션의 프로세스
밖에 있는 HTTP API, SDK, 별도 배포 서비스를 호출하면 외부 호출로 분류한다.

```toml
[tool.taut.external]
modules = ["vendor_sdk"]
wrappers = ["app.adapters.external_call"]

[tool.taut.enum]
shared_modules = ["app.core.enums"]
```

```bash
taut config validate .
taut check .
taut check . --verbose
taut check . --format json
taut rules
taut rules ASYNC001
```

다른 저장소를 로컬 소스로 검사할 수도 있다.

```bash
uvx --no-cache --from /path/to/taut taut check /path/to/project
```

검사 대상 저장소를 전혀 수정하지 않는 일회성 감사에서는 저장소 밖 설정 파일의 절대 경로를
넘긴다.

```bash
taut check /path/to/project --config /path/to/audit-policy.toml
```

설정의 역할 패턴과 `source_roots`는 설정 파일 위치가 아니라 검사 대상 프로젝트를 기준으로 해석한다.
기존 `.policy/policy.toml` 형식은 호환하며, 명시적 `--config`를 사용한 일회성 감사도 유지한다.

## 결과

기본 터미널 출력은 한 문제를 한 줄로 표시하고 마지막에 오류·경고 합계만 보여 준다.
한 줄이 터미널 너비를 넘으면 다음 줄을 들여써 이어서 보여 준다. 터미널이 아닌 로그에서는
120자를 사용하며, 필요하면 `--width 100`처럼 직접 정할 수 있다.
관련 위치, 수정 도움말, 내부 판정 수와 판정 기준이 필요할 때만 `--verbose`를 사용한다.
색상은 터미널에서 자동으로 적용하며 `--color always` 또는 `--color never`로 정할 수 있다.

- 종료값 `0`: 강제 위반 없음
- 종료값 `1`: 강제 위반 있음
- 종료값 `2`: 설정 오류, 분석 실패 또는 강제 규칙 판단 불가

예외가 꼭 필요하면 해당 줄의 정확한 규칙 번호만 무시한다.

```python
legacy_call()  # taut: ignore[ASYNC001]
```

규칙 번호가 없거나 존재하지 않는 ignore는 설정 오류다. 실제 위반이 없는 ignore는
`IGNORE001` 위반이다. 파일 전체 ignore, 기존 위반 목록, 만료일 관리 기능은 없다.

Raw SQL은 전면 허용하지 않는다. 일반 코드는 SQLAlchemy 표현식을 쓰고, 꼭 필요한 Query만
`raw_query_roles`와 `raw_query_wrappers`로 등록한 공용 실행 통로에 둔다. Model의 고정된
`server_default`·부분 Index 조건은 `schema_sql_roles`와 `schema_sql_argument_names`에 맞을 때만
허용한다. 공용 테스트 client 생성 역할은
`tool.taut.code_conventions.test_http_fixture_roles`, 구현을 만들 수 있는
Factory·테스트 조립 역할은 `tool.taut.layers.implementation_construction`에 등록한다.
Adapter 구현 이름이 `Adapter`, `Client`, `Gateway`, `Harness`로 끝나지 않으면
`adapter_implementation_symbols` 또는 `adapter_implementation_suffixes`에 명시한다.

등록한 Raw Query 함수 호출은 `name`, `statement`, `parameters`를 키워드로 명시해야 한다.
`name`과 `statement`에는 고정 문자열만 허용하므로 f-string과 문자열 조합으로 SQL을 만들 수 없다.

## 기본 제공 규칙

기본값인 `strict = true`에서는 `CAT001`만 경고이며 나머지 47개 규칙은 강제다. 규칙을
하나씩 끌 수는 없다. 도입 전에 결과만 확인하려면 `strict = false`로 전체 위반을 경고로
볼 수 있다.

| 묶음 | 규칙 |
|---|---|
| 역할과 구조 | `ARCH000`~`002`, `BOUNDARY001`~`003`, `ENTRY001`, `SERVICE001`, `QUERY001`, `MODEL001`, `ADAPTER001`~`002`, `WIRING001`, `CONFIG001`, `DEPENDS001` |
| 실행 안전 | `TIME001`, `ASYNC001`, `RUNTIME001`, `IMPORT001`, `IMPORT002`, `SIZE001`, `SEC001` |
| DB와 거래 | `TX001`, `TX002`, `SESSION001`~`003`, `ORM001`, `ORM002`, `DB001`, `SQL001` |
| 외부 호출 | `HTTP001`, `LOG001`, `CAT001` |
| 자료 계약 | `DTO001`, `DTO002`, `SNAPSHOT001`, `SCHEMA001`~`003`, `API001`~`003`, `ENUM001`, `EXC001` |
| 테스트 경계 | `TEST001`, `TEST002` |
| 예외 주석 | `IGNORE001` |

규칙은 `prod`, `test`, `migration`, `script` 중 적용할 영역을 스스로 선언한다. 역할 누락,
순환 참조, import 위치, 파일 크기, 동적 실행, async 안전, 보안 접근은 모든 영역에서
검사한다. API·DTO·DB·Service 경계 규칙은 운영 코드에 적용한다.

등록되지 않은 위험 가능 외부 호출은 확정할 수 없으므로 `CAT001` 경고로 표시한다. 호출의
성격을 확인한 뒤 프로젝트 effect 목록에 추가하면 해당 안전 규칙이 정확히 판정한다.

## 개발

```bash
bash scripts/test.sh
bash scripts/test.sh --only tests/unit/policy/test_builtin_rules.py -x
```

전체 검사는 자체 정책 검사, Ruff, mypy strict, Pyright strict, pytest와 90% 이상 분기 포함
coverage, wheel 빌드와 독립 설치를 포함한다.
