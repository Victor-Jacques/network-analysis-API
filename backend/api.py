import datetime
from fastapi import FastAPI
from typing import List

from database import HTTPRequest

app = FastAPI(
    title = "API de monitoramento de tráfego HTTP",
    description = "Fornece dados de tráfego HTTP capturados pelo sniffer",
    version = "0.1.0"
)

MOCK_DATABASE: List[HTTPRequest] = [
    HTTPRequest(
        id = 1,
        timestamp = datetime.datetime.now() - datetime.timedelta(minutes = 5),
        source_ip = "1",
    )
]