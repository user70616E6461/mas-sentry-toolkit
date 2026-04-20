from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class CapturedMessage:
    topic: str
    payload: bytes
    qos: int = 0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    source_client_id: Optional[str] = None

    def payload_str(self) -> str:
        try:
            return self.payload.decode("utf-8")
        except Exception:
            return repr(self.payload)

    def payload_size(self) -> int:
        return len(self.payload)

class BaseProtocolAnalyzer(ABC):
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.messages: List[CapturedMessage] = []
        self.is_running = False

    @abstractmethod
    def connect(self) -> bool:
        pass

    @abstractmethod
    def disconnect(self):
        pass

    @abstractmethod
    def capture(self, duration: int) -> List[CapturedMessage]:
        pass

    @abstractmethod
    def enumerate_topics(self) -> List[str]:
        pass

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_messages": len(self.messages),
            "unique_topics": len(set(m.topic for m in self.messages)),
            "total_bytes": sum(m.payload_size() for m in self.messages),
        }
