from app.errors import AppException, ErrorCode


class UserNotFoundError(AppException):
    code = ErrorCode.USER_NOT_FOUND
