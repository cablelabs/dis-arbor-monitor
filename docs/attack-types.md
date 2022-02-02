# DIS Attack Types

This document describes the AttackType values that can be included in a DIS Attack Report.

Note that an attack can be composed of multiple types and containing multiple metrics - which can be expressed in the Attack Report.

For example:
```json lines
         "attackType" : [
            "tcp-syn", "ssdp-amp"
         ],
         "attributeList" : [
            {
            "unit" : "id",
            "name" : "local_attack_id",
            "value" : "318883"
            },
            {
                "unit" : "bps",
                "name" : "aggregate_attack",
                "value" : 2049345152
            },
            {
                "unit" : "pps",
                "name" : "aggregate_attack",
                "value" : 281140
            },
            {
                "unit" : "bps",
                "name" : "tcp-syn",
                "value" : "1988843"
            },
            {
                "unit" : "bps",
                "name" : "ssdp-amp",
                "value" : "2047356309"
            }
         ], 
         ...
```

Note that attribute metrics are optional as some DDoS detection systems don't provide this data.

## Attack Type Table

| ID/Shortname  | Longname              | Allowed Units | Allowed Values      |Protocols|Dest Ports|Popularity| Description |
| ------------- |-----------------------| --------------|---------------------|---------|----------|----------|-------------|
| SSDP-Amp      | SSDP Amplification    | BPS, PPS      | Positive 64-bit ints| UDP     | 1900     |          | packet size range for request is 90-130 bytes. Packet size range for reply is 248-420 bytes. Amplification factor is 30x. No fragments generated 
| CharGen-Amp   | CharGen Amplification | BPS, PPS      | Positive 64-bit ints| UDP     | 19       | 17       | packet size range for request is 29-76 bytes. Amplification factor is 358.8x
