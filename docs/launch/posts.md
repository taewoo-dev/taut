# Launch copy

Drafts, not published posts. Publish after the updated README, example, and media
are on the default branch and the demo CI check passes. The code blocks below are
copyable post bodies. Attach the [MP4](assets/architecture-demo.mp4) to the X post.

## Show GN

Title: **AI가 어기는 Python 아키텍처 규칙을 검사하는 도구, taut를 만들었습니다**

Link: https://github.com/taewoo-dev/taut

```text
AI에게 “라우터에서 저장소를 직접 호출하지 말고 서비스를 거쳐라”라고 적어두어도,
나중에 코드가 그 규칙에서 벗어나는 문제를 검사로 잡고 싶어 taut를 만들었습니다.

Python 코드에 프로젝트별 역할과 허용 의존 관계를 설정하고, 위반하면 파일 위치와
규칙 ID를 출력하는 도구입니다. 로컬에서 돌리거나 AI에게 JSON 진단을 전달할 수 있고,
CI에서도 같은 검사로 실패를 낼 수 있습니다. 사람이 쓴 코드에도 똑같이 적용됩니다.

레포에 작은 FastAPI 예제를 넣었습니다. 수정 전후 모두 HTTP 요청과 지정된
Ruff·strict mypy·strict Pyright 검사를 통과하지만, 라우터가 저장소를 직접 import하는
버전은 taut에서 ARCH001로 실패합니다. import 한 줄을 서비스로 바꾸면 같은 정책으로
통과합니다. 실제 명령과 버전, 결과도 함께 공개했습니다.

예제는 설명을 위해 수동으로 만든 코드입니다. 영상은 검증된 결과의 리플레이이며,
특정 AI 모델이 생성하거나 수정했다는 실험 결과는 아닙니다.

현재는 Python 3.12+를 지원합니다. 자연어 rules를 전부 자동 변환하거나 설치만으로
에이전트 실행을 강제하지는 않습니다. 프로젝트 정책을 설정하고 검사와 CI에 연결하는
방식입니다. 룰 범위와 알려진 한계는 문서에 적었습니다.

AI로 Python을 개발하는 분과 백엔드 컨벤션을 관리하는 분들의 피드백을 받고 싶습니다.
특히 첫 실행에서 막히는 부분, 검사하고 싶은 규칙, 도입하기 부담스러운 설정이 궁금합니다.
```

Choose **Show**, as required for your own project by the
[GeekNews guidelines](https://news.hada.io/guidelines). A new account must wait one
week before posting links. The submission target is GitHub; Show GN does not
accept YouTube links as the project submission.

## Show HN

Title: **Show HN: Taut – Check Python code against your architecture rules**

URL: https://github.com/taewoo-dev/taut

Author comment:

```text
Hi HN, I made Taut to check project conventions that AI coding instructions can
describe but don't themselves enforce: for example, routers must reach the
repository through a service.

You configure roles and allowed dependencies, and Taut reports violations with
file locations and rule IDs. The same CLI can run locally or in CI, and JSON
diagnostics can be given to a coding agent. It also checks human-written code.

The README has a small, hand-authored FastAPI example. Both variants return the
same HTTP response and pass the documented Ruff, strict mypy, and strict Pyright
checks. Taut flags the forbidden router-to-repository import. Changing that one
import to the service passes the same unchanged policy. The exact commands,
versions, and results are included; this isn't an AI-model benchmark.

The published package is pytaut, the command is taut, and it requires Python 3.12+.
There is no account, API key, or model needed to try the example.

The current tradeoff is onboarding: roles and policy decisions need review before
strict checking. Taut doesn't turn arbitrary prose into guaranteed checks or
automatically attach agent hooks. The docs describe the supported analysis scope.

I'd appreciate feedback on the first-use experience and on architecture rules
you currently enforce manually in review. I'm the author and will answer here.
```

Post when the author can actually answer. Follow the
[Show HN guidelines](https://news.ycombinator.com/showhn.html): a usable project,
no coordinated voting or requests to friends to upvote/comment.

## X: English launch post

```text
Your Python endpoint works. Ruff and type checks pass. But the code skips a required service layer.

I built Taut to check project architecture rules, including in AI-written code.

Hand-authored demo, real results. Python 3.12+.

https://github.com/taewoo-dev/taut
```

Follow-up reply:

```text
The demo changes one import. Both versions use the same policy.

Taut reports the violation; a required CI check can block merging it. Setup is
explicit: no automatic conversion of arbitrary rules or agent-hook installation.

Try it, inspect the exact comparison settings, and tell me where onboarding gets confusing.
```

## First five trial users

For a channel where the author already participates or in response to an
invitation to share projects. This is a feedback request, not a star request.

```text
Python 백엔드용 아키텍처 검사기 taut의 첫 사용 경험을 함께 확인해볼 개발자 5명을 찾습니다.

AI 코딩 도구를 쓰는 분도, 직접 코딩하면서 계층 규칙을 관리하는 분도 좋습니다.
먼저 공개된 작은 FastAPI 예제를 실행해보고, 설치와 진단이 이해되는지 알려주세요.
가능하면 본인 프로젝트 도입까지 시도하며 어디서 막히는지 듣고 싶습니다.

계정·API 키·비공개 코드 공유 없이 예제를 실행할 수 있습니다.
오탐이나 설정 부담도 그대로 듣고 싶습니다.

https://github.com/taewoo-dev/taut
```

For an observation session, ask the participant to open only the public README
first. Record time to first result, whether they understood exit 1, where they
needed help, and whether they would try their own repository. Do not record their
screen or publish a quote without consent. Use the first-use issue form for
asynchronous feedback.
