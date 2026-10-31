"""Safe structured API errors (T5).

Every failure is a ``{"code", "message", "request_id"}`` envelope with
an HTTP status. Messages are fixed strings: no SQL, filesystem paths,
stored exception text or echoed secrets. Validation details expose
only field locations, never input values.
"""

import uuid

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


def new_request_id() -> str:
    return uuid.uuid4().hex


def error_response(status: int, code: str, message: str, request_id: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"code": code, "message": message, "request_id": request_id},
        headers={"X-Request-ID": request_id},
    )


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    request_id = getattr(request.state, "request_id", new_request_id())
    locations = []
    for error in exc.errors():
        loc = ".".join(str(part) for part in error.get("loc", ()))
        locations.append({"field": loc, "message": str(error.get("msg", "invalid value"))})
    return JSONResponse(
        status_code=400,
        content={
            "code": "invalid_request",
            "message": "Request validation failed.",
            "details": locations,
            "request_id": request_id,
        },
        headers={"X-Request-ID": request_id},
    )


async def store_unavailable_handler(request: Request, exc: Exception) -> JSONResponse:
    """Map storage-access failures to a safe structured 503.

    Only the narrow ``StoreUnavailable`` signal is handled here: fixed
    strings with no paths, SQL or exception text. Arbitrary programming
    exceptions are never converted by this handler.
    """
    request_id = getattr(request.state, "request_id", new_request_id())
    return error_response(503, "store_unavailable", "The data store is unavailable.", request_id)
