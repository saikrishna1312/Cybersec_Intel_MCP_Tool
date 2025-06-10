from pydantic import BaseModel
from typing import Optional, List

class CVE(BaseModel):
    cve_id: str
    vulnerability_name: Optional[str] = None
    date_added: Optional[str] = None
    short_description: Optional[str] = None
    required_action: Optional[str] = None
    due_date: Optional[str] = None
    score: Optional[float] = 0.0
    severity: Optional[str] = None
    cweID: Optional[str] = None
    cwe_description: Optional[str] = None
    cwe_name: Optional[str] = None
    extended_description: Optional[str] = None
    consequences: Optional[List] = None
    mitigations: Optional[List] = None
    introductions: Optional[List] = None
    detection_methods: Optional[List] = None
    source: Optional[str] = None
