from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional

class HTTPRequest(BaseModel):
    id: Optional[int] = None
    timestamp: Optional[datetime] = Field(default_factory=datetime.now)
    source_ip: str
    destination_ip: str
    destination_port: int
    http_method: Optional[str] = None
    host: Optional[str] = None
    path: Optional[str] = None


def get_db_connection():

    """Função para retornar a conexão com o banco de dados PostgreSQL"""