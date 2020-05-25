# Name: logFilter.py
# Purpose: library for filtering LogEntry objects (defined in logParser.py)

from .logParser import getFloatTime
import time
import re
import sys
sys.path.insert(0, '/usr/local/mgi/live/lib/python')
import subprocess

###--- Globals ---###

dateTimeRE = re.compile(
    '([0-9]+)/([0-9]+)/([0-9]+)'      # date: mm/dd/yyyy
    ':([0-9]+):([0-9]+):([0-9]+)'     # time: HH:MM:SS
    )

startTime = time.time()
halfHour = 60 * 30

###--- Functions ---###

def parseDateTime(datetime):
    # Purpose: to parse the given datetime into its component parts.  'datetime' is expected
    #    to be formatted as "mm/dd/yyyy:HH:MM:SS"
    # Returns: (year, month, day, hour, minute, second) -- all components as integers
    # Throws: Exception if there are problems parsing the date/time
    
    match = dateTimeRE.match(datetime.strip())
    if not match:
        raise Exception('Cannot parse date/time: %s' % datetime)
    return (int(match.group(3)), int(match.group(1)), int(match.group(2)),
            int(match.group(4)), int(match.group(5)), int(match.group(6)) )

def fetch(url):
    # retrieve the contents of the file at the given 'url' (as a list of strings)
    
    proc = subprocess.run('curl %s' % url, shell=True, capture_output=True, encoding='utf-8')
    if proc.returncode != 0:
    if (exitCode != 0):
        raise Exception('Failed to read from GitHub via:  curl %s' % url)
    return proc.stdout.split('\n')

###--- Classes ---###

class LogFilter:
    # Is: a filter to determine whether to process a given LogEntry or not
    # Note: LogFilters can be chained, so one contains another, which can itself contain
    #    another, and so on.  Each filter is evaluated before the filter it contains, as
    #    it only passes to the chained one if this one passes. Each LogFilter subclass
    #    should only need to implement the _test() method for its particular test.

    def __init__ (self, innerFilter = None):
        # Purpose: constructor; initializes this LogFilter and (optionally) includes another
        #    filter to chain to this one.  (This filter is evaluated first.  If it fails then
        #    then we don't need to evaluate the chained one.  If this one passes, then we do.)
        self.innerFilter = innerFilter
        return
    
    def passes (self, logEntry):
        if self._test(logEntry):
            if self.innerFilter and not self.innerFilter.passes(logEntry):
                return False
            return True
        return False
    
    def _test (self, logEntry):
        # Purpose: to determine if the logEntry passes this particular filter
        # Note: The base LogFilter class is just a pass-through; everything passes the filter.
        #    Subclasses should implement this method to handle particular criteria.
        return True

class DateFilter (LogFilter):
    # Is: a filter that filters LogEntry objects by request date & time.

    def __init__ (self, innerFilter = None, startDateTime = None, endDateTime = None):
        # Note:  If only startDateTime is specified, then all LogEntry objects after (and including)
        #    that date/time will pass.  If only endDateTime is specified, then all LogEntry objects
        #    up to (and including) that time will pass.  If both are specified, then all LogEntry
        #    objects between (and including) those two date/times will pass.  Both date/times are
        #    expected to be formatted as "mm/dd/yyyy:HH:MM:SS"  If neither are specified, the default
        #    setting is for a startDateTime of 30 minutes before the current date/time.
        self.innerFilter = innerFilter
        self.startFloatTime = None
        self.endFloatTime = None
        
        if startDateTime:
            (year, month, day, hour, minute, second) = parseDateTime(startDateTime)
            self.startFloatTime = getFloatTime(year, month, day, hour, minute, second)
        else:
            self.startFloatTime = startTime - halfHour
            
        if endDateTime:
            (year, month, day, hour, minute, second) = parseDateTime(endDateTime)
            self.endFloatTime = getFloatTime(year, month, day, hour, minute, second)
        return
    
    def _test(self, logEntry):
        if self.startFloatTime and logEntry.lt(self.startFloatTime):
            return False
        if self.endFloatTime and logEntry.gt(self.endFloatTime):
            return False
        return True
    
class KnownBotFilter (LogFilter):
    # Is: a filter that filters out LogEntry objects for already-known robots
    
    def __init__ (self, innerFilter = None):
        self.innerFilter = innerFilter
        self.agentStrings = []          # list of User-Agent strings to filter out
        self.ipAddresses = set()        # list of IP addresses to filter out
        self._initialize()
        return 

    def _initialize(self):
        # fetch needed data from the doc_root product at GitHub

        # has the user-agent key strings
        mainConfig = fetch('https://raw.githubusercontent.com/mgijax/doc_root/master/template.cfg')
        
        for line in mainConfig:
            if line.startswith('bots='):
                [ key, values ] = line.split('=')
                for value in values.split(','):
                    self.agentStrings.append(value.strip())
        
        # has the IP addresses that are specifically blocked
        pub1Config = fetch('https://raw.githubusercontent.com/mgijax/doc_root/master/pub1.cfg')
        
        for line in pub1Config:
            if line.startswith('blocked_ips'):
                [ key, values ] = line.split('=')
                for value in values.split(','):
                    self.ipAddresses.add(value.strip())
        return
        
    def _test(self, logEntry):
        if logEntry.ip in self.ipAddresses:
            return False
        
        for key in self.agentStrings:
            if logEntry.userAgent.find(key) >= 0:
                return False
        return True
