# Name: logParser.py
# Purpose: library for parsing Apache access log files

import time
import re

###--- Globals ---###

# regex for parsing an Apache access log entry
logEntryRE = re.compile(
    '^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)'     # IP address
    ' ([^ ]+)'                              # field 2
    ' ([^ ]+)'                              # field 3
    ' \[([0-9]+)/([A-Za-z]+)/([0-9]+)'      # date: dd/mmm/yyyy
    ':([0-9]+):([0-9]+):([0-9]+)'           # time: hh:mm:ss
    ' ([0-9\-]+)'                           # timezone shift (eg: "-500")
    '\] ["]([A-Z]+)'                        # method (eg: "GET" or "POST")
    ' ([^ ]+)'                              # URI
    ' ([^\-]+)/([0-9\.])+["]'               # protocol and version (eg: "HTTP/1.1")
    ' ([0-9]+)'                             # status (eg: "200")
    ' ([0-9\-]+)'                           # bytes transferred
    ' "([^"]+)"'                            # referrer
    ' "([^"]+)"'                            # user agent
    )

# conversion from month abbreviation to its numeric order
months = {
    'Jan' : 1, 'Feb' : 2, 'Mar' : 3, 'Apr' : 4, 'May': 5, 'Jun' : 6,
    'Jul' : 7, 'Aug' : 8, 'Sep' : 9, 'Oct' : 10, 'Nov' : 11, 'Dec' : 12,
    }

badLineCount = 0
badLineSource = {}      # counts by requesting IP

###--- Functions ---###

def defaultErrorHandler(line):
    # Purpose: default error handler for when a line could not be parsed into a LogEntry object
    global badLineCount
    badLineCount = badLineCount + 1
    if line:
        ip = line.split(' ')[0]
        if ip in badLineSource:
            badLineSource[ip] = badLineSource[ip] + 1
        else:
            badLineSource[ip] = 1
    return

def getFaultyLineCount():
    return badLineCount

def getFaultyLineSources():
    return badLineSource.items()

def getNumericMonth(abbrev):
    if abbrev in months:
        return months[abbrev]
    raise Exception('Invalid month: %s' % abbrev)

def getFloatTime(year, month, day, hour, minute, second):
    # returns the time in seconds since the epoch for the given (integer) parameters
    timeStruct = (year, month, day, hour, minute, second, 0, 0, -1)
    return time.mktime(timeStruct)

###--- Classes ---###

class LogEntry:
    # Is: an entry from an Apache access log
    # Has: various fields about the request, its date/time, the requesting IP address, etc.
    # Does: parses the values from a (single-line) Apache access log entry
    
    def __init__ (self, line):
        # Purpose: constructor -- parse 'line' and populate the object
        # Throws: Exception if we cannot parse the line
        match = logEntryRE.match(line)
        if not match:
            raise Exception('Cannot parse "%s"' % line)
        
        self.line = line
        self.ip = match.group(1)
        self.field1 = match.group(2)
        self.field2 = match.group(3)
        self.day = match.group(4)
        self.month = match.group(5)
        self.year = match.group(6)
        self.hour = match.group(7)
        self.minute = match.group(8)
        self.second = match.group(9)
        self.timezone = match.group(10)
        self.method = match.group(11)
        self.uri = match.group(12)
        self.protocol = match.group(13)
        self.version = match.group(14)
        self.status = match.group(15)
        self.bytes = match.group(16)
        self.referrer = match.group(17)
        self.userAgent = match.group(18)
        self.cachedFloatTime = None
        return
    
    def out(self):
        # print this log entry (for debugging)
        print 'IP: %s' % self.ip
        print 'Date: %s %s, %s' % (self.month, self.day, self.year)
        print 'Time: %s:%s:%s' % (self.hour, self.minute, self.second)
        print 'Timezone: %s' % self.timezone
        print 'Request: %s %s' % (self.method, self.uri)
        print 'Protocol: %s (version %s)' % (self.protocol, self.version)
        print 'Status: %s' % self.status
        print 'Sent: %s bytes' % self.bytes
        print 'Referrer: %s' % self.referrer
        print 'User-Agent: %s' % self.userAgent
        return

    def date(self):
        # get date as yyyy/mmm/dd string
        return '%s/%s/%s' % (self.year, self.month, self.day)
    
    def area(self):
        # get the major area for the requested URL (eg- 'marker', 'allele', etc.)
        if self.uri:
            pieces = self.uri.split('/')
            if len(pieces) >= 2:
                return pieces[1]
        return 'N/A'

    def floatTime(self):
        # get the date/time as a number of seconds since the epoch (cache once computed)
        if not self.cachedFloatTime:
            self.cachedFloatTime = getFloatTime(
                int(self.year), getNumericMonth(self.month), int(self.day),
                int(self.hour), int(self.minute), int(self.second))
        return self.cachedFloatTime
    
    def eq(self, targetFloatTime):
        # is this log entry from a certain (float) date/time?
        return targetFloatTime == self.floatTime()
    
    def gt(self, targetFloatTime):
        # is this log entry after a certain (float) date/time (exclusive)?
        return self.floatTime() > targetFloatTime
    
    def lt(self, targetFloatTime):
        # is this log entry before a certain (float) date/time (exclusive)?
        return self.floatTime() < targetFloatTime
    
    def ge(self, targetFloatTime):
        # is this log entry at or after a certain (float) date/time?
        return self.floatTime() >= targetFloatTime
    
    def le(self, targetFloatTime):
        # is this log entry at or before a certain (float) date/time?
        return self.floatTime() <= targetFloatTime
    
class LogIterator:
    # Is: an iterator to go through & help process log entries
    # Does: handles iteration across files and reading of each file
    
    def __init__ (self, inputFilenames, logFilter, entryHandler, errorHandler = None):
        # Purpose: constructor
        # Notes: This object will:
        #    1. will iterate through the given filenames
        #    2. will read each line in each file
        #    3. will create a LogEntry object from each line
        #       a. if #3 fails, then will pass the input line to the errorHandler function
        #       b. otherwise continue to #4
        #    4. see if the LogEntry is passed by the logFilter
        #    5. if so, pass the LogEntry to the entryHandler function
        #       a. if not, continue with next line in #2
        # If 'errorHandler' is None, we will use the default errorHandler() function, which
        # simply counts lines with errors.
        self.inputFilenames = inputFilenames
        self.entryHandler = entryHandler
        self.logFilter = logFilter
        self.errorHandler = errorHandler
        if not errorHandler:
            self.errorHandler = defaultErrorHandler
        return
    
    def go (self):
        # Purpose: sets this iterator to work, processing according to the Notes in the constructor
        # Notes: will return once all lines of all input filenames have been processed
        
        for filename in self.inputFilenames:
            read = 0
            failed = 0
            kept = 0
            discarded = 0
            startTime = time.time()
        
            fp = open(filename, 'r')
            line = fp.readline()
            while line:
                read = read + 1
                try:
                    logEntry = LogEntry(line)
                    if self.logFilter.passes(logEntry):
                        self.entryHandler(logEntry)
                        kept = kept + 1
                    else:
                        discarded = discarded + 1
                except:
                    self.errorHandler(line)
                    failed = failed + 1
                line = fp.readline()
            fp.close()
#            print 'Read %d lines from %s; %d had errors; %d met criteria; %d were skipped (%0.3f sec total)' % (
#                read, filename, failed, kept, discarded, time.time() - startTime)
        return