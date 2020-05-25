#!./python

# Name: findCommonUserAgent.py
# Purpose: find the User-Agents with the most requests

import sys
import os
from shared import *

USAGE = '''Usage: %s <start datetime> <end datetime> <log filename>
''' % sys.argv[0]

###--- Globals ---###

countByUserAgent = {}
ipByAgent = {}

###--- Functions ---###

def uaTracker(entry):
    ua = entry.userAgent
    if ua in countByUserAgent:
        countByUserAgent[ua] = 1 + countByUserAgent[ua]
        ipByAgent[ua][entry.ip] = 1
    else:
        countByUserAgent[ua] = 1
        ipByAgent[ua] = { entry.ip : 1 }
    return

def countCompare(a, b):
    if a[1] != b[1]:
        return cmp(b[1], a[1])      # swapped to sort descending
    return cmp(a[0], b[0])

def commonIpPrefix(ipSet):
    prefix = [ '', '', '', '' ]
    for ip in ipSet:
        if ip.find('.') < 0:
            continue
        octets = ip.split('.')
        for i in range(0,min(4,len(octets))):
            if prefix[i] == '':
                prefix[i] = octets[i]
            elif octets[i] != prefix[i]:
                prefix[i] = 'x' 
    
    prefixStr = '.'.join(prefix)
    if prefixStr == 'x.x.x.x':
        return '[No common IP prefix]'
    return "[from: %s]" % prefixStr

def report():
    items = list(countByUserAgent.items())
    items.sort(countCompare)
    print('Top 25 Hitters per User-Agent:')
    print('------------------------------')
    for (agent, count) in items[:25]:
        print('%10d %s %s' % (count, commonIpPrefix(list(ipByAgent[agent].keys())), agent))
    return
    
###--- Main Program ---###

logParser.LogIterator(
    [sys.argv[3]],
    logFilter.DateFilter(None, sys.argv[1], sys.argv[2]),
    uaTracker).go()
report()
