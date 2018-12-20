#!/usr/local/bin/python

# Name: botfinder.cgi
# Purpose: Similar to findBurstTraffic.py, but wrapped up for web access -- try to identify bots that
#   are sneaking through with traffic to the public server instead of the bot server, identifying
#   them based on traffic patterns.

import os
import sys
sys.path.insert(0, '.')
import time
import cgi
from shared import *

###--- globals ---###

logDir = '/logs/www/public-new'     # where do the log files live?
endTime = time.time()               # default: one hour of traffic up until now
startTime = endTime - 3600.0
error = None

###--- functions ---###

def splitDateTime(dateTime):
    # return (date, time) extracted from dateTime

    i = dateTime.find(':')
    if i < 0:
        raise Exception('Could not find expected colon in "%s"' % dateTime)
    return (dateTime[:i], dateTime[i+1:])

def handleParameters():
    global startTime, endTime, error

    sd, st = splitDateTime(toDateTime(startTime))
    ed, et = splitDateTime(toDateTime(endTime))

    fs = cgi.FieldStorage()
    for key in fs.keys():
        if key == 'startDate':
            sd = fs[key].value
        elif key == 'endDate':
            ed = fs[key].value
        elif key == 'startTime':
            st = fs[key].value
        elif key == 'endTime':
            et = fs[key].value
    
    try:
        (year, month, day, hour, minute, second) = logFilter.parseDateTime('%s:%s' % (sd, st))
        startTime = logParser.getFloatTime(year, month, day, hour, minute, second)

        (year, month, day, hour, minute, second) = logFilter.parseDateTime('%s:%s' % (ed, et))
        endTime = logParser.getFloatTime(year, month, day, hour, minute, second)
    except Exception, e:
        error = e
        return
    
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
    now = startTime

    [ month, day, year ] = getMonthDayYear(endTime)
    endTuple = (year, month, day)

    while nowTuple <= endTuple:
        dates.append('%s.%s.%s' % nowTuple)
        now = now + secondsPerDay
        [ month, day, year ] = getMonthDayYear(now)
        nowTuple = (year, month, day)

    return dates
    
def getLogPaths():
    # look at the global startTime and endTime and return a list of paths to any relevant log files
    global error
    
    dirs = []
    for ymd in getSelectedDates():
        path = os.path.join(logDir, 'access.log.%s' % ymd)
        if os.path.exists(path):
            dirs.append(path)
        else:
            error = 'Cannot find: %s' % path
            sys.stderr.write(error)
    return dirs

def buildTable(title, tableID, sessions):
    # build an output table for the given list of Sessions, headed by the given title
    # returns a single string
    
    out = [
        '<STYLE>',
        '#%s td { border: 1px solid black; max-width:225px; padding: 3px; }' % tableID,
        '#%s th { border: 1px solid black; padding: 3px; background-color: #DDDDDD; padding-left: 3px; padding-right: 15px; padding-top: 3px; padding-bottom: 3px;}' % tableID,
        '#%s { border-collapse: collapse }' % tableID,
        '</STYLE>',
        '<H3>%s</H3>' % title,
        '<TABLE ID="%s">' % tableID,
        '<THEAD>',
        '<TR ID="headerRow">',
        '<TH>IP</TH>',
        '<TH>User-Agent</TH>',
        '<TH>Duration (sec)</TH>',
        '<TH>Total Hits</TH>',
        '<TH>Robot Likelihood</TH>',
        '<TH>Peak Hits<br/>(30 min)</TH>',
        '<TH>Peak Hits<br/>(1 min)</TH>',
        '<TH>Avg Hits<br/>(1 min)</TH>',
        '<TH>Data Areas</TH>',
        '</TR>',
        '</THEAD>',
        '<TBODY>',
        ]
    
    for session in sessions:
        areaCounts = session.getTotalHitsByArea()
        areas = areaCounts.keys()
        areas.sort()
        a = '%d Areas: %s (%d)' % (len(areas), areas[0], areaCounts[areas[0]])
        for area in areas[1:]:
            a = '%s, %s (%d)' % (a, area, areaCounts[area])

        out = out + [
            '<TR>'
            '<TD>%s</TD>' % session.ip,
            '<TD>%s</TD>' % session.userAgent,
            '<TD>%s</TD>' % session.getDuration(),
            '<TD>%s</TD>' % session.getTotalHits(),
            '<TD>%0.3f</TD>' % session.getRobotLikelihood(),
            '<TD>%s</TD>' % session.getPeakHitsPer(1800),       # half hour = 1800 seconds
            '<TD>%s</TD>' % session.getPeakHitsPerMinute(),
            '<TD>%0.3f</TD>' % session.getHitsPerMinute(),
            '<TD>%s</TD>' % a,
            '</TR>',
            ]
    out.append('</TBODY></TABLE>')
    return '\n'.join(out)

def report(tracker):
    # build the page of output for the given tracker
    
    sd, st = splitDateTime(toDateTime(startTime))
    ed, et = splitDateTime(toDateTime(endTime))

    errorMessage = ''
    if error:
        errorMessage = '<B>Error: %s</B><P>' % error
        
    out = [
        'Content-type: text/html',
        '',
        '<HTML><HEAD><TITLE>botfinder output</TITLE><HEAD><BODY>',
        '<FORM ACTION="botfinder.cgi" METHOD="GET">',
        '<H2>botfinder output</H2>',
        '<i>Seeking previously unidentified robots from ',
        '<INPUT TYPE="text" NAME="startDate" SIZE="10" VALUE="%s" TITLE="start date (mm/dd/yyyy)"> ' % sd, 
        '<INPUT TYPE="text" NAME="startTime" SIZE="8" VALUE="%s" TITLE="start time (hh:mm:ss)"> ' % st, 
        ' to ',
        '<INPUT TYPE="text" NAME="endDate" SIZE="10" VALUE="%s" TITLE="end date (mm/dd/yyyy)"> ' % ed, 
        '<INPUT TYPE="text" NAME="endTime" SIZE="8" VALUE="%s" TITLE="end time (hh:mm:ss)">' % et, 
        '</i><INPUT TYPE="submit" VALUE="Go"><br/>',
        '<i>Note that time periods longer than 15 hours tend to result in timeouts.<br/>',
        errorMessage,
        buildTable('Top-50 Most Likely Robot Sessions', 'robotTable', tracker.getMostLikelyRobotSessions(50)),
        
        '</FORM>',
        # include JQuery libraries
        '<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>',
        '<link rel="stylesheet" href="https://cdn.datatables.net/1.10.19/css/jquery.dataTables.min.css" />',
        '<script src="https://cdn.datatables.net/1.10.19/js/jquery.dataTables.min.js"></script>',
        '<script>',
        '''$(document).ready( function () {
            $("#robotTable").DataTable( {paging : false} );
            // sort by Robot Likelihood column, descending
            $('th')[4].click();
            $('th')[4].click();
            } );''',
        '</script>',
    ]
    out.append('</BODY></HTML>')
    print '\n'.join(out)
    return

###--- main program ---###

if __name__ == '__main__':
    handleParameters()

    tracker = sessionTracker.SessionTracker()
    logParser.LogIterator(
        getLogPaths(),
        logFilter.DateFilter(logFilter.KnownBotFilter(), toDateTime(startTime), toDateTime(endTime)),
        tracker.track).go()
    report(tracker)