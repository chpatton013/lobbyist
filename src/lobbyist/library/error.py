from typing import Any, Dict, Set, Tuple


class HttpError(Exception):
    def __init__(
        self,
        code: int,
        name: str,
        description: str,
        context: Dict[str, str] = {},
    ):
        super().__init__(code, description)
        self.code = code
        self.name = name
        self.description = description
        self.context = context

    def into_response(self) -> Tuple[Dict[str, Any], int]:
        payload = {}
        if self.name:
            payload["error"] = self.name
        if self.description:
            payload["error_description"] = self.description
        if self.context:
            payload["error_context"] = self.context
        return (payload, self.code)


class ClientError(HttpError):
    pass


class BadRequestError(ClientError):
    def __init__(self, description: str, **context):
        super().__init__(400, "invalid_request", description, context)


class UnauthorizedError(ClientError):
    def __init__(self, description: str):
        super().__init__(401, "invalid_client", description)


class ForbiddenError(ClientError):
    def __init__(self, description: str):
        super().__init__(403, "", description)


class NotFoundError(ClientError):
    def __init__(self, description: str):
        super().__init__(404, "", description)


class NotAcceptableError(ClientError):
    def __init__(self, **context):
        super().__init__(406, "", "cannot meet accept constraints", context)


class ConflictError(ClientError):
    def __init__(self, **context):
        super().__init__(409, "", "integrity constraint failure", context)
