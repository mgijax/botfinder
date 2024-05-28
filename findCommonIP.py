#!./python

# Name: findCommonIP.py
# Purpose: find the IP addresses with the most requests

import sys
import os
from shared import *

USAGE = '''Usage: %s <start datetime> <end datetime> <log filename>
''' % sys.argv[0]

###--- Globals ---###

countByIP = {}
agentByIP = {}

###--- Functions ---###

def ipTracker(entry):
    ip = entry.ip
    if ip in countByIP:
        countByIP[ip] = 1 + countByIP[ip]
    else:
        countByIP[ip] = 1
        agentByIP[ip] = entry.userAgent
    return

def countCompare(ab):
    return (a[1], a[0])

def report():
    items = list(countByIP.items())
    items.sort(key=countCompare)
    for (ip, count) in items[:15]:
        print('%10d %s %s' % (count, ip, agentByIP[ip]))
    print()
    print('%d lines could not be parsed; common offenders:' % logParser.getFaultyLineCount())
    
    items = logParser.getFaultyLineSources()
    items.sort(key=countCompare)
    for (ip, count) in items[:15]:
        print('%10d %s' % (count, ip))
    
    return
    
###--- Main Program ---###

logParser.LogIterator(
    [sys.argv[3]],
    logFilter.DateFilter(None, sys.argv[1], sys.argv[2]),
    ipTracker).go()
report()
