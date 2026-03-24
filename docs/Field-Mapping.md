# Field Mapping Reference

This document maps every H3C Comware syslog field ID to its output SGBox key representation.

## Core Fields (always present in output)

| H3C Field | ID | SGBox Key | Description | Example Values |
|-----------|------|-----------|-------------|----------------|
| `Protocol` | 1001 | `proto` | Network protocol | TCP, UDP, ICMP |
| `SrcIPAddr` | 1003 | `src` | Source IP address | 10.1.1.10 |
| `DstIPAddr` | 1007 | `dst` | Destination IP address | 8.8.8.8 |
| `SrcPort` | 1004 | `sport` | Source port | 52314 |
| `DstPort` | 1008 | `dport` | Destination port | 443 |
| `Event` | 1048 | `action` | Derived action (see below) | permit, deny, close |

## Extended Fields (included in "extended" output mode)

| H3C Field | ID | SGBox Key | Description | Example Values |
|-----------|------|-----------|-------------|----------------|
| `Application` | 1002 | `app` | Application type | cPanel, dns, ntp, l2tp |
| `Category` | 1174 | `category` | Traffic category | Protocol, Other_Service |
| `NatSrcIPAddr` | 1005 | `nat_src` | NAT source IP | 102.134.120.153 |
| `NatSrcPort` | 1006 | `nat_sport` | NAT source port | 49868 |
| `NatDstIPAddr` | 1009 | `nat_dst` | NAT destination IP | 10.17.0.13 |
| `NatDstPort` | 1010 | `nat_dport` | NAT destination port | 443 |
| `InitPktCount` | 1044 | `init_pkts` | Initiator packet count | 1 |
| `InitByteCount` | 1046 | `init_bytes` | Initiator byte count | 60 |
| `RplyPktCount` | 1045 | `reply_pkts` | Reply packet count | 0 |
| `RplyByteCount` | 1047 | `reply_bytes` | Reply byte count | 0 |
| `BeginTime_e` | 1013 | `start_time` | Session start time | 03132026162020 |
| `EndTime_e` | 1014 | `end_time` | Session end time | — |
| `RuleId` | 1249 | `rule_id` | Matching rule ID | 0 |
| `SrcAddrTransConfig` | 1247 | `src_nat_type` | Source NAT type | NAT_server, Not_translated |
| `DstAddrTransConfig` | 1248 | `dst_nat_type` | Dest NAT type | NAT_server, Not_translated |
| `VlanID` | 1175 | `vlan_id` | VLAN identifier | -- |
| `VNI` | 1213 | `vni` | Virtual network ID | -- |

## Action Mapping

The `Event(1048)` field is mapped to a clean `action` value by the parsing engine:

| Event Code | Event Description | SGBox Action |
|------------|-------------------|-------------|
| `(1)` | Session denied | `deny` |
| `(2)` | Session denied (policy) | `deny` |
| `(8)` | Session created | `permit` |
| `(9)` | Session deleted | `close` |
| `(10)` | Session aged out | `close` |

## Output Examples

### Core Format
```text
proto=TCP src=68.183.184.83 dst=102.134.120.157 sport=46644 dport=22 action=permit
```

### Extended Format
```text
proto=TCP src=68.183.184.83 dst=102.134.120.157 sport=46644 dport=22 action=permit app=cPanel category=Other_Service nat_src=68.183.184.83 nat_dst=10.17.0.13 nat_sport=46644 nat_dport=22 init_pkts=1 init_bytes=60 reply_pkts=0 reply_bytes=0 src_nat_type=Not_translated dst_nat_type=NAT_server hostname=Gole-F1000-Firewall-01
```
