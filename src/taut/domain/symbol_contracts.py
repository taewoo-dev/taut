from enum import StrEnum


class ContractKind(StrEnum):
    DTO = "dto"
    REQUEST = "request"
    RESPONSE = "response"
    ENUM = "enum"
    EXCEPTION = "exception"
    SNAPSHOT = "snapshot"
