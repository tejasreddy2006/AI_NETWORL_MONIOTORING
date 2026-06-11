"""NetGuard AI — SQLAlchemy models package.

Importing this module makes every model class available at the package
level so that ``from app.models import Packet, Alert, …`` works.
"""

from app.models.packet import Packet
from app.models.alert import Alert
from app.models.device import Device, DeviceLink
from app.models.prediction import MLPrediction, MLModel
from app.models.health import HealthScore
from app.models.geo_traffic import GeoTraffic
from app.models.simulation import SimulationResult
from app.models.conversation import AIConversation

__all__ = [
    "Packet",
    "Alert",
    "Device",
    "DeviceLink",
    "MLPrediction",
    "MLModel",
    "HealthScore",
    "GeoTraffic",
    "SimulationResult",
    "AIConversation",
]
