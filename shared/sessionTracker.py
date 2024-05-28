# Name: sessionTracker.py
# Purpose: to help identify "sessions" (by traffic pattern, not by cookie or other means) and
#   let us do computations on them.

import sys
import math

def endSlice(myList, num):
    # assumes myList is sorted in ascending order.  Returns the last 'num' items in
    # descending order.
    
    sublist = myList[-num:]
    sublist.reverse()
    return sublist

def scale (measurement):
    # return a scaled (float) version of the given measurement, so large numbers aren't overwhelming
    # when combined with smaller ones
    
    if measurement <= 0.0:
        return 0.0
    return math.log(measurement)

class SessionTracker:
    # Is: a tracker that helps sort LogEntry objects into appropriate sessions
    # Has: sets of Session objects, each with data about their LogEntry objects
    
    def __init__ (self, maxGap = 300):
        # constructor; 'maxGap' defines how large a gap of seconds is allowed between hits of
        #    a single Session
        self.activeSessions = {}        # IP address -> Session object
        self.oldSessions = []           # list of Session o bjects that are no longer active
        self.maxGap = maxGap
        self.latestTime = 0.0           # latest time we've seen so far
        return
    
    def track(self, entry):
        # add the given LogEntry to an appropriate Session object
        
        if (entry.ip in self.activeSessions) and (not self.activeSessions[entry.ip].isIn(entry)):
            # We've seen this IP address before, but this entry is after its gap expired, so retire
            # the old session and start a new one.
            self.oldSessions.append(self.activeSessions[entry.ip])
            self.activeSessions[entry.ip] = Session(self.maxGap)

        elif (entry.ip not in self.activeSessions):
            # We haven't seen this IP address before, so it's definitely a new session.
            self.activeSessions[entry.ip] = Session(self.maxGap)
            
        self.activeSessions[entry.ip].add(entry)
        self.latestTime = max(self.latestTime, entry.floatTime())
        return
    
    def finalize(self):
        # move all active Session objects tob e considered 'old'
        for (ip, session) in list(self.activeSessions.items()):
            self.oldSessions.append(session) 
            self.activeSessions = {}
        return
    
    def report(self):
        print('Active Sessions: %d' % len(self.activeSessions))
        print('Old Sessions: %d' % len(self.oldSessions))
        print()
        return
    
    def getSessionCount(self):
        # get a count of all sessions processed so far
        return len(self.activeSessions) + len(self.oldSessions)
    
    def getLongestSessions(self, num = 25):
        # get the top 'num' sessions sorted by duration from most to least
        self.finalize()
        
        def sortByDuration(a):
            # inner function; used for sorting in this method
            return a.getDuration()
        
        self.oldSessions.sort(key=sortByDuration)
        return endSlice(self.oldSessions, num)
    
    def getSessionsWithMostHits(self, num = 25):
        # get the top 'num' sessions sorted by total hit count from most to least
        self.finalize()

        def sortByTotalHits(a):
            # inner function; used for sorting in this method
            return a.getTotalHits()
        
        self.oldSessions.sort(key=sortByTotalHits)
        return endSlice(self.oldSessions, num)
    
    def getMostLikelyRobotSessions(self, num = 25):
        # get the top 'num' sessions scored from most likely to be a robot to least
        self.finalize()
        def sortByRobotLikelihood(a):
            # inner function; used for sorting in this method
            return a.getRobotLikelihood()
        
        # Sorting is too slow for a large number of sessions; we need to work with a smaller list.
        # We'll keep the 'num' highest scoring sessions seen so far.  Any session with a lower score
        # doesn't need to be considered further.  Any session with a higher score can get put in the
        # list and a lower scoring one will get bumped out.

        i = num                                         # iterates through sessions
        topSessions = self.oldSessions[:i]              # highest 'num' sessions found so far
        topSessions.sort(key=sortByRobotLikelihood)

        sessionCount = len(self.oldSessions)
        i = i + 1
        
        while i < sessionCount:
            session = self.oldSessions[i]
            botLikelihood = session.getRobotLikelihood()
            if botLikelihood > topSessions[0].cachedRobotScore:
                j = 0
                while (j < num) and (botLikelihood > topSessions[j].cachedRobotScore):
                    j = j + 1

                topSessions.insert(j - 1, session)
                del topSessions[0]
            
            i = i + 1 
        
        return topSessions
    
class Session:
    # Is: a group of hits from a single IP address that occurred with a gap between hits no larger
    #    than the given 'maxGap'

    def __init__ (self, maxGap):
        self.maxGap = maxGap        # maximum gap (in seconds) between hits for them to be part of the same session
        self.earliestTime = None    # earliest time (in seconds) for a hit in this session
        self.latestTime = None      # latest time (in seconds) for a hit in this session
        self.hits = []
        self.hitsByArea = {}
        self.ip = None
        self.cachedRobotScore = None
        self.userAgent = None
        self.peakCache = {}         # maps from number of seconds to peak traffic for that size time slice
        return
    
    def getExpirationTime (self):
        # return the time (in seconds) at which a hit can no longer be part of this session
        return self.latestTime + self.maxGap
    
    def isIn(self, entry):
        # determine if the given LogEntry object is allowed to be part of this Session or not
        
        if (self.ip == None) and (self.latestTime == None):
            # first entry into a session is always allowed
            return True

        elif (self.ip == entry.ip) and (entry.floatTime() <= (self.latestTime + self.maxGap)):
            # if IP address matches and the log entry is before the allowed gap expires, then the entry is
            # part of this session
            return True

        # otherwise, the entry needs to be part of a different session
        return False
    
    def add(self, entry):
        # add the given entry to this Session (throw an Exception if this entry is not allowed in
        # this session because of a different IP address or too big a time gap since the last hit)
        
        if not self.isIn(entry):
            raise Exception('Failed to add an entry to a non-matching session')

        entryTime = entry.floatTime()
        if (self.ip == None) and (self.latestTime == None):
            # first entry for a session sets the standard for the user's IP address and the timings
            self.ip = entry.ip
            self.earliestTime = entryTime
            self.latestTime = entryTime
            self.userAgent = entry.userAgent
        else:
            self.earliestTime = min(entryTime, self.earliestTime)
            self.latestTime = max(entryTime, self.latestTime)
            
        self.hits.append(entryTime)

        area = entry.area()
        if area not in self.hitsByArea:
            self.hitsByArea[area] = 1
        else:
            self.hitsByArea[area] = 1 + self.hitsByArea[area]
        return
    
    def getDuration (self):
        # get the total length of the session (in seconds)

        if self.latestTime == None:
            return 0
        return int(self.latestTime - self.earliestTime)
    
    def getTotalHits (self):
        # get the total number of hits in this session
        return len(self.hits)
    
    def getTotalHitsByArea (self):
        # get the number of hits broken down by content area
        # returns:  { 'area1' : hit count, 'area2' : hit count, ... }
        return self.hitsByArea
    
    def getHitsPerMinute (self):
        # return the average number of hits per minute for the session (as a float)
        
        duration = max(60.0, self.getDuration())    # session of at least one minute
        return 1.0 * self.getTotalHits() / duration * 60.0
    
    def getPeakHitsPer (self, seconds=300):
        # For a time period of the length defined by 'seconds', find and return the highest
        # number of hits in a timeslice of that size for this session.
        
        if not self.hits:
            return 0.0
        
        if seconds not in self.peakCache:
            bins = []       # each bin is [start time, end time, count of hits]
            for entryTime in self.hits:
                bins.append( [entryTime, entryTime + seconds, 0] )
            
            for entryTime in self.hits:
                for bin in bins:
                    if bin[0] <= entryTime <= bin[1]:
                        bin[2] = bin[2] + 1

            peak = max([bin[2] for bin in bins])
            self.peakCache[seconds] = peak
        return self.peakCache[seconds]

    def getPeakHitsPerMinute (self):
        # return the highest number of hits in this session within a single minute
        # (convenience wrapper)
        return self.getPeakHitsPer(60)
    
    def getRobotLikelihood (self):
        # get a score for how likely this session is to be a robot rather than a human user.
        
        if self.cachedRobotScore == None:
            # Increased robot likelihood for:
            #    1. high peak number of hits for a half hour 
            #    2. high average number of hits per minute
            #    3. high peak number of hits for one minute
            #    4. high number of total hits
            #    5. long session duration
            #    6. large number of different data areas
        
            self.cachedRobotScore = 0.35 * scale(self.getPeakHitsPer(1800)) \
                + 0.30 * scale(self.getHitsPerMinute()) \
                + 0.25 * scale(self.getPeakHitsPerMinute()) \
                + 0.20 * scale(self.getTotalHits()) \
                + 0.15 * scale(self.getDuration()) \
                + 0.05 * scale(len(self.getTotalHitsByArea()))

        return self.cachedRobotScore
