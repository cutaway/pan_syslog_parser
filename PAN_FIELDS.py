# PAN_FIELDS.py - fields for Palo Alto Syslog Entries. 
# 
# Copyright Don C. Weber <cutawaysecurity@gmail.com>
# This file is part of pan_syslog_parser.
# 
# pan_syslog_parser is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# pan_syslog_parser is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Point Of Contact:    Don C. Weber <cutawaysecurity@gmail.com>
#
#################################
# Name: pan_syslog_parser.py
# Author: Don C. Weber (cutaway)
# Start Data: 20160314
# Last Update: 20160315
#
# Primary Resource for PAN Fields:
# https://www.paloaltonetworks.com/documentation/61/pan-os/pan-os/reports-and-logging/syslog-field-descriptions.html
#
# TODO:
#   Update for PAN > 7
#   Update for all PAN Log Types
#   Implement STDIN
#   Update PAN_FIELDS to handle normal entries as well as custom entries
#   Update PAN_FIELDS to handle all Log Types of PAN log enties
#################################

# TODO: The pan fields should be layered similar to scapy. Split this into different log types.
# TODO: Determine Firewall Version and update for those before and after 6.1

TYPE_FIELD = 3

pan_traffic_fields_ordered = { \
    0:"Time_Stamp", \
    1:"Serial_Number", \
    2:"Log_Type", \
        # Traffic, Threat, Config, System and Hip-Match
    3:"Subtype", \
        # Start, End, Drop, Deny
    4:"Repeat_count", \
    5:"Generate_Time", \
    6:"Source_IP", \
    7:"Destination_IP", \
    8:"NAT_Source_IP", \
    9:"NAT_Destination_IP", \
    10:"Rule_Name", \
    11:"Source_User", \
    12:"Destination_User", \
    13:"Application", \
    14:"Virtual_System", \
    15:"Source_Zone", \
    16:"Destination_Zone", \
    17:"Inbound_Interface", \
    18:"Outbound_Interface", \
    19:"Log_Forwarding_Profile", \
    20:"RX_time", \
    21:"Session_ID", \
    22:"Repeat_Count_ICMP", \
    23:"Source_Port", \
    24:"Destination_Port", \
    25:"NAT_Source_Port", \
    26:"NAT_Destingtaion_Port", \
    27:"Flags", \
        # 32-bit field that provides details on session
    28:"IP_Protocol", \
    29:"Action", \
    30:"Bytes", \
    31:"Bytes_Sent", \
    32:"Bytes_Received", \
    33:"Packets", \
    34:"Start_Time", \
    35:"Elapsed_Time_Sec", \
    36:"Category", \
    37:"Nat_Src_RESEARCH", \
    38:"Sequence_Number", \
    39:"Action_Flags", \
    40:"Source_Location", \
    41:"Destination_Location", \
    42:"Nat_Dst_RESEARCH", \
    43:"Packets_sent", \
    44:"Packets_Received",
    #45:"Session_End_Reason"   # PA Version 6.1 Only
    45:"Session_End_Reason",
    46:"dg_hier_level_1",
    47:"dg_hier_level_2",
    48:"dg_hier_level_3",
    49:"dg_hier_level_4",
    50:"Virtual_System_Name",
    51:"Device_Name",
    52:"Action_Source",
    53:"UKNOWN0",
    54:"UKNOWN1",
    55:"UKNOWN2",
    56:"UKNOWN3",
    57:"UKNOWN4",
    58:"UKNOWN5",
    59:"UKNOWN6",
    60:"UKNOWN7",
}
# Generate name fields
pan_traffic_fields_names = [ v for k, v in pan_traffic_fields_ordered.iteritems() ]
# NOTE: For legacy purposes
pan_traffic_fields = pan_traffic_fields_names

pan_threat_fields_ordered = { \
    0:"Time_Stamp",
    1:"Serial_Number",
    2:"Log_Type",
    3:"Subtype",
    4:"Repeat_count",
    5:"Generated_Time",
    6:"Source_IP",
    7:"Destination_IP",
    8:"NAT_Source_IP",
    9:"NAT_Destination_IP",
    10:"Rule_Name",
    11:"Source_User",
    12:"Destination_User",
    13:"Application",
    14:"Virtual_System",
    15:"Source_Zone",
    16:"Destination_Zone",
    17:"Inbound_Interface",
    18:"Outbound_Interface",
    19:"Log_Forwarding_Profile",
    20:"RX_time",
    21:"Session_ID",
    22:"Repeat_Count",
    23:"Source_Port",
    24:"Destination_Port",
    25:"NAT_Source_Port",
    26:"NAT_Destination_Port",
    27:"Flags",
    28:"Protocol",
    29:"Action",
    30:"Miscellaneous",
    31:"Threat_ID",
    32:"Category",
    33:"Severity",
    34:"Direction",
    35:"Sequence_Number",
    36:"Action_Flags",
    37:"Source_Location",
    38:"Destination_Location",
    39:"FUTURE_USE_0",
    40:"Content_Type",
    41:"PCAP_id",
    42:"Filedigest",
    43:"Cloud",
    44:"URL_Index",
    45:"User_Agent",
    46:"File_Type",
    47:"X-Forwarded-For",
    48:"Referer",
    49:"Sender",
    50:"Subject",
    51:"Recipient",
    52:"Report_ID",
    53:"Device_Group_Hierarchy_Level_1",
    54:"Device_Group_Hierarchy_Level_2",
    55:"Device_Group_Hierarchy_Level_3",
    56:"Device_Group_Hierarchy_Level_4",
    57:"Virtual_System_Name",
    58:"Device_Name",
    59:"FUTURE_USE_1"
}
# Generate name fields
pan_threat_fields_names = [ v for k, v in pan_threat_fields_ordered.iteritems() ]
# NOTE: For legacy purposes
pan_threat_fields = pan_threat_fields_names

pan_subtypes = {
    0:"Start", \
    1:"End", \
    2:"Drop", \
    3:"Deny"
}
pan_subtypes_names = [ v for k, v in pan_subtypes.iteritems() ]

pan_log_types = {
    0:"TRAFFIC", \
    1:"THREAT", \
    2:"CONFIG", \
    3:"SYSTEM", \
    4:"HIP-MATCH"
}
pan_log_types_names = [ v for k, v in pan_log_types.iteritems() ]
