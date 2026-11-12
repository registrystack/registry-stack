from flask import Flask

from .connection import Connection

def install(app: Flask, stack: Connection, *, request_seconds: float) -> None: ...
