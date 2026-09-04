"""Email analysis endpoint (architected for later email-gateway integration)."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..audit import audit
from ..security import CurrentUser, client_ip, get_optional_user
from ..services.email_analyzer import EmailAnalyzer

router = APIRouter(prefix="/api/email", tags=["email"])


class LinkIn(BaseModel):
    text: str = Field(default="", max_length=2000)
    href: str = Field(default="", max_length=4096)


class AttachmentIn(BaseModel):
    filename: str = Field(default="", max_length=512)
    mime_type: str = Field(default="", max_length=128)


class EmailIn(BaseModel):
    from_header: str = Field(min_length=1, max_length=1000)
    reply_to: str = Field(default="", max_length=1000)
    subject: str = Field(default="", max_length=2000)
    body: str = Field(default="", max_length=20000)
    links: list[LinkIn] = Field(default_factory=list)
    attachments: list[AttachmentIn] = Field(default_factory=list)


@router.post("/analyze")
def analyze_email(
    body: EmailIn,
    request: Request,
    user: Optional[CurrentUser] = Depends(get_optional_user),
):
    analyzer = EmailAnalyzer(org_id=user.org_id if user else 1)
    result = analyzer.analyze_email(
        from_header=body.from_header,
        reply_to=body.reply_to,
        subject=body.subject,
        body=body.body,
        links=[l.model_dump() for l in body.links],
        attachments=[a.model_dump() for a in body.attachments],
    )
    audit(action="ANALYZE_EMAIL", actor_id=user.id if user else None,
          actor_email=user.email if user else "anonymous",
          org_id=user.org_id if user else 1, ip=client_ip(request),
          new={"classification": result.classification,
               "risk_score": result.risk_score,
               "sender_domain": result.sender_domain})
    return result.to_dict()