class UserResponse:
    @classmethod
    def from_internal(cls, data: object) -> "UserResponse":
        return cls(name=data.name)
