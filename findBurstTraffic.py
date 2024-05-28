#!/opt/python3.8/bin/python3

# Name: findBurstTraffic.py
# Purpose: find IP addresses that have been issuing requests frequently

import sys
sys.path.insert(0, '/usr/local/mgi/live/lib/python')
import os
from shared import *

USAGE = '''Usage: %s <start datetime> <end datetime> <log filename>
''' % sys.argv[0]

###--- Globals ---###

tracker = sessionTracker.SessionTracker()

###--- Functions ---###

def reportSection(title, sessions):
    print title
    print '-' * len(title)
    for session in sessions:
        print 'IP: %s' % session.ip
        print 'User-Agent: %s' % session.userAgent
        print 'Duration (sec): %d' % session.getDuration()
        print 'Total Hits: %d' % session.getTotalHits()
        print 'Robot Likelihood: %0.3f' % session.getRobotLikelihood()
        print 'Peak Hits (half hour): %d' % session.getPeakHitsPer(1800)
        print 'Hits per Minute: %0.3f' % session.getHitsPerMinute()
        print 'Peak Hits (1 minute): %d' % session.getPeakHitsPerMinute()
        areaCounts = session.getTotalHitsByArea()
        areas = areaCounts.keys()
        areas.sort()
        print 'Data Areas (%d): %s (%d)' % (len(areas), areas[0], areaCounts[areas[0]]),
        for area in areas[1:]:
            print ', %s (%d)' % (area, areaCounts[area]),
        print
        print
    print
    return

def report():
    tracker.report()
    reportSection('Sessions with Longest Duration', tracker.getLongestSessions())
    reportSection('Sessions with Most Hits', tracker.getSessionsWithMostHits())
    reportSection('Sessions with Highest Robot Likelihood', tracker.getMostLikelyRobotSessions())
    return
    
###--- Main Program ---###

logParser.LogIterator(
    [sys.argv[3]],
    logFilter.DateFilter(logFilter.KnownBotFilter(), sys.argv[1], sys.argv[2]),
    tracker.track).go()
report()
