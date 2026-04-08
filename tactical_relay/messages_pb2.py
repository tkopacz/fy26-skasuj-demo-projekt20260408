"""
Protobuf message definitions for the tactical relay service.

Generated dynamically using google.protobuf descriptor API since protoc is not
available in air-gapped environments. Implements TacticalMessage and DeliveryAck
with the same API as protoc-generated code.
"""

from __future__ import annotations

import google.protobuf.descriptor_pb2 as _descriptor_pb2
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database

_sym_db = _symbol_database.Default()

# ---------------------------------------------------------------------------
# Build the FileDescriptorProto programmatically
# ---------------------------------------------------------------------------

_fdp = _descriptor_pb2.FileDescriptorProto()
_fdp.name = "messages.proto"
_fdp.package = "tactical"
_fdp.syntax = "proto3"

# ---------- TacticalMessage ----------
_tm = _fdp.message_type.add()
_tm.name = "TacticalMessage"

def _field(msg, name, number, ftype, label=_descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL):
    f = msg.field.add()
    f.name = name
    f.number = number
    f.type = ftype
    f.label = label
    return f

_F = _descriptor_pb2.FieldDescriptorProto
_field(_tm, "message_id",   1, _F.TYPE_STRING)
_field(_tm, "sender",       2, _F.TYPE_STRING)
_field(_tm, "recipients",   3, _F.TYPE_STRING, _F.LABEL_REPEATED)
_field(_tm, "priority",     4, _F.TYPE_UINT32)
_field(_tm, "classification", 5, _F.TYPE_STRING)
_field(_tm, "content_type", 6, _F.TYPE_STRING)
_field(_tm, "payload",      7, _F.TYPE_BYTES)
_field(_tm, "timestamp",    8, _F.TYPE_INT64)
_field(_tm, "ttl_seconds",  9, _F.TYPE_UINT32)

# ---------- DeliveryAck ----------
_da = _fdp.message_type.add()
_da.name = "DeliveryAck"

_field(_da, "message_id", 1, _F.TYPE_STRING)
_field(_da, "recipient",  2, _F.TYPE_STRING)
_field(_da, "status",     3, _F.TYPE_STRING)
_field(_da, "timestamp",  4, _F.TYPE_INT64)

# ---------------------------------------------------------------------------
# Register the descriptor in the global pool
# ---------------------------------------------------------------------------

_pool = _descriptor_pool.DescriptorPool()
_pool.Add(_fdp)

_TACTICAL_MESSAGE_DESC = _pool.FindMessageTypeByName("tactical.TacticalMessage")
_DELIVERY_ACK_DESC = _pool.FindMessageTypeByName("tactical.DeliveryAck")

# ---------------------------------------------------------------------------
# Create Python message classes
# ---------------------------------------------------------------------------

try:
    # protobuf ≥ 4.21 (upb backend)
    from google.protobuf import message_factory as _mf

    _classes = _mf.GetMessages([_fdp])
    TacticalMessage = _classes["tactical.TacticalMessage"]
    DeliveryAck = _classes["tactical.DeliveryAck"]

except Exception:
    # Fallback: use reflection (older protobuf or pure-python backend)
    from google.protobuf import reflection as _refl

    TacticalMessage = _refl.MakeClass(_TACTICAL_MESSAGE_DESC)
    DeliveryAck = _refl.MakeClass(_DELIVERY_ACK_DESC)

_sym_db.RegisterMessage(TacticalMessage)
_sym_db.RegisterMessage(DeliveryAck)

__all__ = ["TacticalMessage", "DeliveryAck"]
