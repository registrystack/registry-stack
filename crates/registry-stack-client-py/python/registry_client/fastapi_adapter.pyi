from fastapi import FastAPI

from .connection import Connection

def install(app: FastAPI, stack: Connection, *, request_seconds: float) -> None: ...
