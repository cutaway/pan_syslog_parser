# pan_syslog_parser.py - functions to parse and display data from Palo Alto Syslog Entries. 
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
# TODO:
#   Update for PAN > 7
#   Update for all PAN Log Types
#   Implement STDIN
#   Update PAN_FIELDS to handle normal entries as well as custom entries
#   Update PAN_FIELDS to handle all Log Types of PAN log enties
#   Consolidate print functions
#################################

import PAN_FIELDS as pnf
from colorama import Fore
import sys
from copy import copy
import time

# Global Variables
DEBUG  = False
TAG    = True
COLOR  = False
header = "<PAN_SYSLOG"
footer = ">"

def usage():
    print "pan_syslog_parser.py:  This script will parse PAN Syslog Messages for analysis."
    print ""
    print "-h:                  print usage information"
    print "-f <file>:           Input file (required). For STDIN pass - (dash). NOTE: STDIN Not Implemented yet."
    print "-o <outfile>:        Output file - default is to STDOUT"
    print "-j:                  Limit output to Fields 7,8,30,25,31."
    print "-J:                  Limit output to Fields 6,7,8,9,10,11,12,14,24,25,29,30,31."
    print "-F <8,9,31,26,32>:   Limit output to user defined fields. Input expects a comma separated list with no spaces: 7,8,30,25,31."
    print "-c:                  Enable color output."
    print "-t:                  Do not tag output with Scapy-style header and footer fields."
    print "-T:                  Print timestamps to standard out to show start and stop times for run."
    print "-s:                  Use Destination address to build IPINFO Search lines to cut and paste or put into scripts. Does NOT automatically make query."
    print "-int:                Print a list of internal IP addresses"
    print "-ext:                Print a list of external IP addresses"
    sys.exit()
    
##############################
# Print Functions
##############################
# Input: data = dictionary of values, no color formatting
def print_entry(data, ONF = ''):

    # Create printable line
    #line = ' '.join(data) + "\n"
    line = []
    if TAG: line.append(header)
    if data['Log_Type'] == "TRAFFIC":
        #for e in range(len(pnf.pan_traffic_fields_ordered)):
        for e in range(len(data.keys())):
            if COLOR: 
                line.append(Fore.MAGENTA + pnf.pan_traffic_fields_ordered[e] + Fore.BLUE + "= " + Fore.GREEN + data[pnf.pan_traffic_fields_ordered[e]])
            else:
                line.append(pnf.pan_traffic_fields_ordered[e] + "= " + data[pnf.pan_traffic_fields_ordered[e]])
    if data['Log_Type'] == "THREAT":
        #for e in range(len(pnf.pan_threat_fields_ordered)):
        for e in range(len(data.keys())):
            if COLOR: 
                line.append(Fore.MAGENTA + pnf.pan_threat_fields_ordered[e] + Fore.BLUE + "= " + Fore.GREEN + data[pnf.pan_threat_fields_ordered[e]])
            else:
                line.append(pnf.pan_threat_fields_ordered[e] + "= " + data[pnf.pan_threat_fields_ordered[e]])
    if TAG: line.append(footer)

    if not ONF:
        print ' '.join(line)
    else:
        ONF.write(' '.join(line))

# TODO: Consolidate this with the regular print function
def print_fields(data, fields = [7,8,30,25,31], ONF = ''):

    # Copy fields because, for some reason, this local variable is altering the original
    #print "DEBUG:",fields
    in_fields = copy(fields)
    line = []
    # Format for color
    if TAG: 
        line.append(header)
        for e in in_fields:
            if data['Log_Type'] == "TRAFFIC": line.append(Fore.MAGENTA + pnf.pan_traffic_fields_ordered[e] + Fore.BLUE + "= " + Fore.GREEN + data[pnf.pan_traffic_fields_ordered[e]])
            if data['Log_Type'] == "THREAT": line.append(Fore.MAGENTA + pnf.pan_threat_fields_ordered[e] + Fore.BLUE + "= " + Fore.GREEN + data[pnf.pan_threat_fields_ordered[e]])
        line.append(footer)
    else:
        for e in in_fields:
            if data['Log_Type'] == "TRAFFIC": line.append(data[pnf.pan_traffic_fields_ordered[e]])
            if data['Log_Type'] == "THREAT": line.append(data[pnf.pan_threat_fields_ordered[e]])
    if not ONF:
        print ' '.join(line)
    else:
        ONF.write(' '.join(line))

##############################
# Info Gathering Functions
##############################
def print_dest_ipinfo(data, ONF = ''):

    # Set URL
    ipinfo = "curl http://ipinfo.io/"

    # Append IP address from external source
    if data['Source_Zone'] == 'outside':
        dest = data['Source_IP']
    else:
        dest = data['Destination_IP']

    if not ONF:
        print ipinfo + dest
    else:
        ONF.write(line)

def print_ip(data, internal = 0, ONF = ''):

    # List of external IP addresses
    ip = []

    if internal: 
        dest = 'inside'
    else:
        dest = 'outside'

    if data['Source_Zone'] == dest:
        ip.append(data['Source_IP'])
    else:
        ip.append(data['Destination_IP'])

    for e in ip:
        if not ONF:
            print e
        else:
            ONF.write(e)

##############################
# Data Parsing Functions
##############################
# data = one line of PAN Syslog
# return = one dictionary of scapy-style parsed data
def scapy_lines(data):

    # Split line into a List
    tmp = data.split(',')

    # Make a dictionary of values
    dl = {}

    # Build dictionary. Color and Tags should be handled by print function
    #print tmp
    for i in range(len(tmp)):
        if tmp[pnf.TYPE_FIELD] == "TRAFFIC": dl[pnf.pan_traffic_fields[i]] = tmp[i]
        if tmp[pnf.TYPE_FIELD] == "THREAT": dl[pnf.pan_threat_fields[i]] = tmp[i]
    return dl

##############################
# Main Function
##############################
if __name__ == "__main__":

    # Control Variables
    STDIN   = False
    TIME    = False
    IPINFO  = False
    FIELDS  = False
    TARGET  = False
    user_fields = ''
    fields  = []
    ONF     = ''
    inf     = ''

    ###############################
    # Process Command Line Options
    # This is a popular switch method that can be used instead of argparser.
    ###############################
    ops = ['-h','-f','-o','-c','-j','-J','-F','-t','-T','-s','-int','-ext']

    cnt = 0
    while len(sys.argv) > 1:
        op = sys.argv.pop(1)
        if op == '-h':
            usage()
        if op == '-f':
            inf = sys.argv.pop(1)
            if inf == "-":
                print sys.argv[0] + ": STDIN Not Implemented Yet"
                sys.exit()
                # Implement for future usage
                inf = sys.stdin
                STDIN = True
        if op == '-o':
            onf = sys.argv.pop(1)
            ONF = open(onf,'w')
        if op == '-c':
            COLOR = True
        if op == '-j':
            # awk -F, '{ print $7 " " $8 " " $30 " " $25 " " $31 }
            FIELDS = True
            fields = [7,8,30,25,31]
            cnt += 1
        if op == '-J':
            # awk -F ',' '{print $6,"IP",$7,"->",$8,"NATIP",$9,"->",$10,"RULE",$11,"USER",$12,"APP",$14,"PORT",$24,"->",$25,$29,$30,"TOTAL BYTES",$31}'
            FIELDS = True
            fields = [6,7,8,9,10,11,12,14,24,25,29,30,31]
            cnt += 1
        if op == '-F':
            FIELDS = True
            user_fields = sys.argv.pop(1)
            fields = user_fields.split(',')
            # Convert to int from str
            for e in range(len(fields)):
                fields[e] = int(fields[e])
            cnt += 1
        if op == '-t':
            TAG = False
        if op == '-T':
            TIME = True
        if op == '-s':
            IPINFO = True
            cnt += 1
        if op == '-int':
            TARGET = True
            loc    = 1
            cnt += 1
        if op == '-ext':
            TARGET = True
            loc    = 0
            cnt += 1
        if op not in ops:
            print "Unknown option:"
            usage()

    # Test for user input
    if not inf or (cnt > 1):
        usage()
    ###############################

    # Print start time for reference
    if TIME: print "PAN SYSLOG Parser Start:",
    if TIME: print time.strftime("%Y-%m-%d %H:%M:%S")
    if TIME: print

    # Get data
    if STDIN:
        # Copy data from STDIN so we aren't working with original data
        in_data = copy(inf)
    else:
        # Read data from file
        in_data = open(inf,'r').readlines()

    # data = array for parsed log line
    data = []
    for e in in_data:
        data.append(scapy_lines(e.rstrip()))

    # Print each line to where the user wants
    for e in data:
        if IPINFO:
            print_dest_ipinfo(e,ONF)
            continue
        if FIELDS:
            print_fields(e,fields = fields,ONF = ONF)
            continue
        if TARGET:
            print_ip(e,internal = loc,ONF = ONF)
            continue
        print_entry(e,ONF)

    # Close output file or file might remain empty because data still in buffer
    if ONF: ONF.close()
        
    # Print start time for reference
    if TIME: print "\n\nPAN SYSLOG Parser Finish:",
    if TIME: print time.strftime("%Y-%m-%d %H:%M:%S")
    if TIME: print "Happy Hunting...\n\n"
