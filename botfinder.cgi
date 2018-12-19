#!/usr/local/bin/python

# Name: botfinder.cgi
# Purpose: Similar to findBurstTraffic.py, but wrapped up for web access -- try to identify bots that
#   are sneaking through with traffic to the public server instead of the bot server, identifying
#   them based on traffic patterns.

import sys
sys.path.insert(0, '.')
import time
import cgi
from shared import *

###--- globals ---###

logDir = '/logs/www/public-news'    # where do the log files live?
endTime = time.time()               # one hour of traffic up until now
startTime = endTime - 3600.0

###--- functions ---###

def handleParameters():
    global script, startTime, endTime

    fs = cgi.FieldStorage()
    for key in fs.keys():
        if key == 'startDate':
            pass
        elif key == 'endDate':
            pass
        elif key == 'startTime':
            pass
        elif key == 'endTime':
            pass
        
    # ensure that the times are ordered properly
    if startTime > endTime:
        c = endTime
        endTime = startTime
        startTime = c
    return

def toDateTime(floatTime):
    # convert floatTime (seconds since the epoch) to a string representation of the date/time
    return time.strftime('%m/%d/%Y:%H:%M:%S', time.localtime(floatTime))

def getMonthDayYear(floatTime):
    # get the numeric [ month, day, year ] for the given float time (seconds since epoch)
    s = toDateTime(floatTime)
    return s.split(':')[0].split('/')

def getSelectedDates():
    # get a list of selected dates (each 'YYYY.mm.dd') that include data from startTime to endTime
    
    secondsPerDay = 60 * 60 * 24
    dates = []

    [ month, day, year ] = getMonthDayYear(startTime)
    nowTuple = (year, month, day)

    [ month, day, year ] = getMonthDayYear(endTime)
    endTuple = (year, month, day)


    while nowTuple <= endTuple:
        dates.append('%s.%s.%s' % nowTuple)
        now = now + secondsPerDay
        [ month, day, year ] = getMonthDayYear(now)

    return dates
    
def getLogPaths():
    # look at the global startTime and endTime and return a list of paths to any relevant log files
    
    dirs = []
    for ymd in getSelectedDates():
        path = os.path.join(logDir, ymd)
        if os.path.exists(path):
            dirs.append(path)
    return dirs

def buildTable(title, tableID, sessions):
    # build an output table for the given list of Sessions, headed by the given title
    # returns a single string
    
    out = [
        '<H3>%s</H3>' % title,
        '<TABLE ID="%s">' % tableID,
        '<THEAD>',
        '<TR ID="headerRow">',
        '<TH>IP</TH>',
        '<TH>User-Agent</TH>',
        '<TH>Duration (sec)</TH>',
        '<TH>Total Hits</TH>',
        '<TH>Robot Likelihood</TH>',
        '<TH>Peak Hits (30 min)</TH>',
        '<TH>Peak Hits (1 min)</TH>',
        '<TH>Avg Hits (1 min)</TH>',
        '<TH>Data Areas</TH>',
        '</TR>',
        '</THEAD>',
        '<TBODY>',
        ]
    
    for session in sessions:
        areas = areaCounts.keys()
        areas.sort()
        a = '%d Areas: %s (%d)' % (len(areas), areas[0], areaCounts[areas[0]]),
        for area in areas[1:]:
            a = a + ', %s (%d)' % (area, areaCounts[area]),

        out = out + [
            '<TR>'
            '<TD>%s</TD>' % session.ip,
            '<TD>%s</TD>' % session.userAgent,
            '<TD>%s</TD>' % session.getDuration(),
            '<TD>%s</TD>' % session.getTotalHits(),
            '<TD>%s</TD>' % session.getRobotLikelihood(),
            '<TD>%s</TD>' % session.getPeakHitsPer(1800),       # half hour = 1800 seconds
            '<TD>%s</TD>' % session.getPeakHitsPerMinute(),
            '<TD>%s</TD>' % session.getHitsPerMinute(),
            '<TD>%s</TD>' % a,
            '</TR>',
            ]
    out.join('</TBODY></TABLE>')
    return '\n'.join(out)

def report(tracker):
    # build the page of output for the given tracker
    
    out = [
        '<HTML><HEAD><TITLE>botfinder output</TITLE><HEAD><BODY>',
        '<H2>botfinder output</H2>',
        '<H3>%s to %s</H3>' % (toDateTime(startTime), toDateTime(endTime)),
        buildTable('Most Likely Robots', 'robotTable', tracker.getMostLikelyRobotSessions()),
    ]
    out.append('</BODY></HTML>')

###--- main program ---###

if __name__ == '__main__':
    handleParameters()

    tracker = sessionTracker.SessionTracker()
    logParser.LogIterator(
        getLogPaths(),
        logFilter.DateFilter(logFilter.KnownBotFilter(), toDateTime(startTime), toDateTime(endTime)),
        tracker.track).go()
    report(tracker)