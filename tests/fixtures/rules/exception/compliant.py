from app.errors import AppException, ErrorCode


class UserNotFoundError(AppException):
    code = ErrorCode.USER_NOT_FOUND

    def __init__(self):
        super().__init__(error_code=ErrorCode.USER_NOT_FOUND)
