import requests
from typing import Dict
from uuid import uuid4
from pydantic import IPvAnyAddress
from pydantic.types import Json, UUID4
from typing import List, Optional
from pydantic import BaseModel, Json, HttpUrl

try:
    from devtools import debug as print
except:
    pass


class EventAttribute(BaseModel):
    enum: str
    name: str
    value: Optional[str]
    metadata: Optional[Json]


class IpAttribute(BaseModel):
    enum: str
    name: str
    value: Optional[str]
    metadata: Optional[Json]


class DisClient(object):
    """SDK for the /data route for the DIS system.  Implements the REST API. """

    def __init__(self, api_key: str, base_url: HttpUrl = "https://api.dissarm.net/v1", staged_limit=0):
        self._key = api_key
        self._base_url = base_url
        self._staged_limit = stage_limit
        self._events = {}

        res = requests.get(f"{base_url}/client/me?api_key={api_key}")

        if res.status_code == 401:
            raise Exception(
                "Not authorized.  Check that your API Key is correct.")

        if res.status_code >= 400:
            raise Exception(res.json())

        self._me = res.json()

    def get_info(self):
        return self._me

    def get_dest(self):
        return self._dest_url

    def add_attack_event(self, start_timestamp: int,
                         end_timestamp: int,
                         attack_type: List[str] = None):
        """Stages an Event Attack to the outgoing DIS ingestion data.  Returns an ID to be used to reference the event in the SDK"""

        if self._staged_limit and len(self._events) == self._staged_limit:
            raise Exception(f"Too many staged events ({self._staged_limit})")

        event_uuid = str(uuid4())
        self._events[event_uuid] = {
            "startTimestamp": start_timestamp,
            "endTimestamp": end_timestamp,
            "attackType": attack_type,
            "ipAddressList": [],
            "attributeList": []
        }

        return event_uuid

    def update_event_end_timestamp(self, event_uuid: UUID4, end_timestamp: int):
        """Updates the end timestamp of an attack event"""
        self._events[event_uuid]["endTimestamp"] = end_timestamp

    def add_attribute_to_event(self, event_uuid: UUID4, name: str, enum: str, value: str, metadata: Dict = None):
        if not event_uuid in self._events:
            raise Exception("Event does not exist")

        self._events[event_uuid]["attributeList"].append({
            "enum": enum,
            "name": name,
            "value": value,
            "metadata": metadata
        })

    def add_attack_source_to_event(self,
                                   event_uuid: UUID4,
                                   ip: IPvAnyAddress,
                                   start_timestamp: int = None,
                                   end_timestamp: int = None,
                                   attack_type: List[str] = None,
                                   attribute_list: List[IpAttribute] = None):
        """Adds an IP Address (attack source) to an existing Attack Event"""
        if not event_uuid in self._events:
            raise Exception("Event does not exist")

        self._events[event_uuid]["ipAddressList"].append({
            "ipAddress": ip,
            "startTimestamp": start_timestamp,
            "endTimestamp": end_timestamp,
            "attackType": attack_type,
            "attributeList": attribute_list
        })

    def get_staged_event_ids(self):
        """Returns all staged event ids in DisClient"""
        return [k for k, v in self._events.items()]

    def send(self):
        """Sends all staged attack events to DIS and clears staged events"""

        events = []
        for k, v in self._events.items():
            events.append(v)

        res = requests.post("{0}/data?api_key={1}".format(self._base_url, self._key), json={"events": events})

        if 200 <= res.status_code < 400:
            self._events = {}
            return f"Sent {len(events)} events to {self._base_url} (status {res.status_code} ({res.reason}))"

        if 500 <= res.status_code < 600 or res.status_code == 401:
            # Can be remedied on the server side - throw an error but don't clear the queue
            raise Exception(f"DIS server returned recoverable server error status code {res.status_code} ({res.reason}) - {len(events)} reports queued")

        if 400 <= res.status_code < 500:
            # Not considered recoverable - so clear the queue
            self._events = {}
            raise Exception(f"DIS server returned client error status code {res.status_code} ({res.reason})")

