# 문서 안내

릴리스 사용자는 [`../MIGRATION.md`](../MIGRATION.md)와 [`VALIDATION_REPORT.md`](VALIDATION_REPORT.md)를
먼저 확인한다. 이 문서 세트는 pytaut 0.4.0, 설정 schema v3, Python 3.12+ 기준이다.

## 현재 구현 기준

- `architecture/foundation-abstractions.md`: 엔진 단계와 자료 이동
- `architecture/builtin-policy.md`: 기본 백엔드 역할과 48개 규칙
- `architecture/development-quality-gates.md`: 이 저장소의 완료 검사
- `05_taut_overview.html`: 현재 구조와 실행 흐름 시각화
- [`architecture/taut-system-architecture.html`](architecture/taut-system-architecture.html): 핵심 구조·계층·판정 흐름 인터랙티브 맵
- [`performance.md`](performance.md): disk cache와 resident daemon의 재현 가능한 성능 계약
- [`operations.md`](operations.md): cache/daemon 운영 방식과 보안 경계

현재 동작이 문서와 다르면 코드, 자동 테스트, 위 세 문서를 함께 고쳐야 한다.

`architecture/policy-engine-design-review.md`는 구현 전 설계를 현재 구조와 대조한 기록이다.
현재 명령, 설정 형식, 규칙 수, 예외 처리 방식은 위 현재 구현 문서와 코드를 기준으로 한다.
