"""Shared safe errors, usable by the isolated controller without Django startup."""


class RuleError(Exception):
    def __init__(self, code, message, status=409):
        self.code, self.message, self.status = code, message, status
        super().__init__(message)
