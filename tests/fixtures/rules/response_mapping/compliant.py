class UserResponse:
    @classmethod
    def from_internal(cls, data):
        return cls(name=data.name)
