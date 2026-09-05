# 문서 안내

릴리스 사용자는 [`../MIGRATION.md`](../MIGRATION.md)와 [`VALIDATION_REPORT.md`](VALIDATION_REPORT.md)를
먼저 확인한다. 이 문서 세트는 pytaut 0.7.0, 설정 schema v5, Python 3.12+ 기준이다.

## 현재 구현 기준

- [`configuration-conventions.md`](configuration-conventions.md): 신규 파일 자동 분류, 역할 규약, 설정 간소화와 정책 준수 전환

- [`architecture/taut-system-architecture.html`](architecture/taut-system-architecture.html): 핵심 구조·계층·판정 흐름 인터랙티브 맵
- [`getting-started.md`](getting-started.md): 신규 설치부터 AI 보정, audit/check 반복, CI 적용까지의 사용자 가이드
- [`performance.md`](performance.md): disk cache와 resident daemon의 재현 가능한 성능 계약
- [`performance-roadmap.md`](performance-roadmap.md): 조사 근거, 단계별 최적화 순서, 정확성·성능 진입 조건
- [`operations.md`](operations.md): cache/daemon 운영 방식과 보안 경계
- [`plugins.md`](plugins.md): 외부 rule pack과 fact provider 공개 계약 및 설치 예시
- [`VALIDATION_REPORT.md`](VALIDATION_REPORT.md): 재현 가능한 릴리스 검증 절차와 최신 결과

현재 동작이 문서와 다르면 코드, 자동 테스트, 위 문서를 함께 고쳐야 한다. 현재 명령,
설정 형식, 규칙 수, 예외 처리 방식은 README와 추적되는 문서 및 코드를 기준으로 한다.
