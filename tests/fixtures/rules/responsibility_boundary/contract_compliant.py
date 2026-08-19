from dataclasses import dataclass


@dataclass(frozen=True)
class PaymentResult:
    identifier: str
