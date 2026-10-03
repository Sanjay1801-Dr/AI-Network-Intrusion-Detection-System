"""Pydantic schemas for network traffic records."""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, IPvAnyAddress


class TCPFlags(BaseModel):
    """TCP flag indicators."""

    syn: int = Field(0, ge=0)
    ack: int = Field(0, ge=0)
    rst: int = Field(0, ge=0)
    fin: int = Field(0, ge=0)


class TrafficRecordBase(BaseModel):
    """Base schema attributes for traffic record."""

    captured_at: Optional[datetime] = None
    source_ip: str = Field(..., example="192.168.1.100")
    destination_ip: str = Field(..., example="10.0.0.1")
    source_port: int = Field(..., ge=0, le=65535)
    destination_port: int = Field(..., ge=0, le=65535)
    protocol: str = Field(..., example="TCP")
    duration_seconds: float = Field(0.0, ge=0.0)
    total_packets: int = Field(0, ge=0)
    total_bytes: int = Field(0, ge=0)
    syn_flag_count: int = Field(0, ge=0)
    ack_flag_count: int = Field(0, ge=0)
    rst_flag_count: int = Field(0, ge=0)
    fin_flag_count: int = Field(0, ge=0)


class TrafficRecordCreate(TrafficRecordBase):
    """Schema for ingesting a single traffic flow."""
    pass


class TrafficBatchIngest(BaseModel):
    """Schema for batch ingestion of network traffic flows."""

    batch_id: Optional[str] = None
    records: List[TrafficRecordCreate]


class TrafficRecordResponse(TrafficRecordBase):
    """Schema returned when reading a traffic record."""

    id: str
    is_suspicious: bool

    class Config:
        from_attributes = True
