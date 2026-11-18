from dataclasses import dataclass, field
from email import message_from_string, policy
from email.message import Message

from app.models import Attachment


def parse_headers(headers_raw: str) -> Message:
    """Parse raw headers. The stdlib parser unfolds multi-line headers and never raises on junk."""
    return message_from_string(headers_raw, policy=policy.default)


@dataclass
class ParsedMessage:
    """What every analyzer sees: parsed headers plus the bodies."""
    headers: Message
    text: str = ""
    html: str = ""
    attachments: list[Attachment] = field(default_factory=list)
