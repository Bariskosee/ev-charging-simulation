"""
Static metadata for charging points used by driver dashboards.

In a full deployment this would come from an asset registry service.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional

def load_cp_cities(filepath: str) -> dict:
    mapping = {}
    with open(filepath, "r") as f:
        for line in f:
            cp_id, city = line.strip().split(",")
            mapping[cp_id] = city
    return mapping

cp_to_city = load_cp_cities("/app/evcharging/common/CP_cities.txt")

@dataclass(frozen=True)
class ChargingPointMetadata:
    cp_id: str
    name: str
    address: str
    city: str
    latitude: float
    longitude: float
    connector_type: str
    power_kw: float
    amenities: List[str]


METADATA: Dict[str, ChargingPointMetadata] = {
    "CP-001": ChargingPointMetadata(
        cp_id="CP-001",
        name="Central Plaza A1",
        address="123 Main St",
        city=cp_to_city["CP-001"],
        latitude=40.7128,
        longitude=-74.0060,
        connector_type="Type 2",
        power_kw=22.0,
        amenities=["Restrooms", "Coffee", "WiFi"],
    ),
    "CP-002": ChargingPointMetadata(
        cp_id="CP-002",
        name="Harbor Fast Charge",
        address="5 Harbor Ave",
        city=cp_to_city["CP-002"],
        latitude=40.7000,
        longitude=-74.0100,
        connector_type="CCS",
        power_kw=150.0,
        amenities=["24/7", "Restrooms"],
    ),
    "CP-003": ChargingPointMetadata(
        cp_id="CP-003",
        name="Airport Lot C",
        address="Airport Rd",
        city=cp_to_city["CP-003"],
        latitude=40.6890,
        longitude=-74.1745,
        connector_type="Type 2",
        power_kw=11.0,
        amenities=["Parking", "Security"],
    ),
    "CP-004": ChargingPointMetadata(
        cp_id="CP-004",
        name="Shopping Mall West",
        address="789 Retail Blvd",
        city=cp_to_city["CP-004"],
        latitude=40.7200,
        longitude=-74.0200,
        connector_type="CCS",
        power_kw=50.0,
        amenities=["Shopping", "Restaurants", "WiFi"],
    ),
    "CP-005": ChargingPointMetadata(
        cp_id="CP-005",
        name="Downtown Garage B",
        address="42 Park St",
        city=cp_to_city["CP-005"],
        latitude=40.7150,
        longitude=-74.0080,
        connector_type="Type 2",
        power_kw=22.0,
        amenities=["Covered", "24/7", "Security"],
    ),
    "CP-006": ChargingPointMetadata(
        cp_id="CP-006",
        name="Highway Rest Stop",
        address="Mile 45 Interstate",
        city=cp_to_city["CP-006"],
        latitude=40.6800,
        longitude=-74.1500,
        connector_type="CCS",
        power_kw=150.0,
        amenities=["24/7", "Restrooms", "Vending"],
    ),
    "CP-007": ChargingPointMetadata(
        cp_id="CP-007",
        name="University Campus",
        address="100 College Ave",
        city=cp_to_city["CP-007"],
        latitude=40.7300,
        longitude=-74.0300,
        connector_type="Type 2",
        power_kw=11.0,
        amenities=["Student Access", "WiFi"],
    ),
    "CP-008": ChargingPointMetadata(
        cp_id="CP-008",
        name="Tech Park North",
        address="250 Innovation Dr",
        city=cp_to_city["CP-008"],
        latitude=40.7400,
        longitude=-74.0400,
        connector_type="CCS",
        power_kw=50.0,
        amenities=["Business Hours", "WiFi"],
    ),
    "CP-009": ChargingPointMetadata(
        cp_id="CP-009",
        name="Sports Arena",
        address="500 Stadium Way",
        city=cp_to_city["CP-009"],
        latitude=40.7050,
        longitude=-74.0150,
        connector_type="Type 2",
        power_kw=22.0,
        amenities=["Event Parking", "Restrooms"],
    ),
    "CP-010": ChargingPointMetadata(
        cp_id="CP-010",
        name="Beachfront Plaza",
        address="1 Ocean Drive",
        city=cp_to_city["CP-010"],
        latitude=40.6700,
        longitude=-74.0050,
        connector_type="CCS",
        power_kw=150.0,
        amenities=["Scenic View", "24/7", "Restrooms"],
    ),
}


def get_metadata(cp_id: str) -> Optional[ChargingPointMetadata]:
    """Return metadata for a charging point, if available."""
    return METADATA.get(cp_id)

