#!/usr/bin/env python
#=====================#################
#           )        (         (      #
#    (   ( /(  (     )\ ) *   ))\ )   #
#    )\  )\()) )\   (()/(` )  /(()/(  #
#  (((_)((_)((((_)(  /(_)) )(_))(_))  #
#  )\___ _((_)\ _ )\(_))(_(_())_))_   #
# ((/ __| || (_)_\(_) _ \_   _||   \  #
#  | (__| __ |/ _ \ |   / | |  | |) | #
#   \___|_||_/_/ \_\|_|_\ |_|  |___/  #
#                                     #
#    chartd.py - Chart.d - (v0.1)     #
#                                     #
# DATE                                #
# 12/11/2014                          #
#                                     #
# DESCRIPTION                         #
# Chart.d - Tiny A record DNS server  #
# designed for 802.11 phishing        #
# campaigns and acting as a malicious #
# DNS server                          #
#                                     #
# AUTHOR                              #
# Jacques "Spacecow" Pharand          #
#                                     #
#######################################


import re
import os
import sys
import json
import socket
import os.path
import logging
import argparse

try:
    import redis
except(ImportError):
    sys.stderr.write('{0}: Dependencies not met: Redis required for full functionality')
    sys.exit(5)

chartdLogger = logging.getLogger('Pequod.chartd')
chartdLogger.setLevel(logging.INFO)
try:
    socket.SO_REUSEPORT
except(AttributeError):
    socket.SO_REUSEPORT = 15


class Chartd(object):
    """Tiny host(A) record DNS server"""

    def __init__(self, defaultAddress='127.0.0.1', useRedis=False, redisAddress='localhost', redisPort=6379):
        self.defaultAddress = defaultAddress
        self.useRedis       = useRedis
        self.redisAddress   = redisAddress
        self.redisPort      = redisPort
        self.zoneRecords    = {}
        self.configuration  = {}

    def loadConfiguration(self, configuration='conf/chartd.conf'):
        """Load a configuration file in to self.configuration"""

        chartdLogger.debug('Attempting to load configuration file {0}'.format(configuration))
        if not os.path.isfile(configuration):
            chartdLogger.error('Could not find {0}: Does not exist'.format(configuration))
            raise IOError('Configuration file \'{0}\' not found'.format(configuration))

        with open(configuration, 'r') as config:
            configContent = config.read()
            try:
                configuration = json.loads(configContent)
                chartdLogger.info('Succesfully loaded configuration file {0}'.format(configuration))
            except():  # What is the exception it needs to catch?
                configuration = {}
                chartdLogger.error('Could not properly read configuration file {0}: JSON SyntaxError'.format(configuration))
            finally:
                self.configuration = configuration

        return self.configuration

    def loadZoneFile(self, zoneFile='conf/chartd.zone'):
        """Load a JSON zone file in to memory"""

        chartdLogger.debug('Attempting to load zone file {0}'.format(zoneFile))
        if not os.path.isfile(zoneFile):
            chartdLogger.error('Could not find {0}: Doesnot exist'.format(zoneFile))
            raise IOError('Zone file \'{0}\' not found'.format(zoneFile))

        if self.useRedis:
            with open(zoneFile, 'r') as f:
                try:
                    zoneContent = f.read()
                    zoneRecords = json.loads(zoneContent)
                except():
                    zoneRecords = {}

            redisdb = redis.StrictRedis(host=self.redisAddress, port=self.redisPort, db=0)
            for key in zoneRecords.keys():
                redisdb.set(key, zoneRecords[key])

        else:
            with open(zoneFile, 'r') as f:
                zoneContent = f.read()
                try:
                    zoneRecords = json.loads(zoneContent)
                    chartdLogger.info('Succesfully loaded configuratioin file {0}'.format(zoneFile))
                except():
                    zoneRecords = {}
                    chartdLogger.error('Could not properly read zone file {0}: JSON SyntaxError'.format(zoneFile))
                finally:
                    self.zoneRecords = zoneRecords

            return self.zoneRecords

    def remoteResolve(self, domain):
        """Attempt to resolve a domain using socket.gethostname()"""

        try:
            IPAddress = socket.gethostbyname(domain)
            chartdLogger.info('Translated: {0} <-> [{1}]'.format(domain, IPAddress))
            if not self.useRedis:
                self.zoneRecords[domain] = IPAddress
        except(socket.gaierror):
            IPAddress = self.defaultAddress
        finally:
            return IPAddress

    def localResolve(self, domain):
        """Look up domain in local/remote cache"""

        if domain[-1] != '.':
            domain = domain + '.'
        chartdLogger.debug('Attempting to resolve domain {0} locally'.format(domain))

        if self.useRedis:
            try:
                pass
                # Need to revisit with more Redis and python driver knowledge
                #redisServer = redis.Redis(self.redisAddress)
                #ARecord = redisServer.hget('chartd.domains', domain)
                #redisServer.close()
            except:
                chartdLogger.warning('No connection with redis server [{0}]'.format(self.redisAddress))
                ARecord = self.defaultAddress

            if ARecord is not None:
                chartdLogger.info('Translated: {0} <-> [{1}]'.format(domain, ARecord))
                return ARecord
            else:
                chartdLogger.warning('Entry for domain {0} not found in database'.format(domain))
                return self.defaultAddress

        else:
            if domain in self.zoneRecords.keys():
                chartdLogger.info('Host {0} found in local cache'.format(domain))
                return self.zoneRecords[domain]
            else:
                chartdLogger.warning('Entry for domain {0} not found in cache'.format(domain))
                return self.defaultAddress

    def mainloop(self):
        """Start chart.d daemon and bind to port"""

        chartdLogger.info('Starting chart.d under PID: {0}'.format(os.getpid()))
        global UDPSocket
        UDPSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            UDPSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except(socket.error):  # Swallowing errors is fun :D
            chartdLogger.error('SO_REUSEPORT not supported by this system')
        UDPSocket.bind(('', 53))

        while True:
            IPAddress = ''
            data, sourceAddress = UDPSocket.recvfrom(1024)
            packet = DNSQuery(data)
            IPAddress = self.localResolve(packet.domain)
                # If our localResolve failed and fell back to our default address
            if self.configuration['FORWARD_NOMATCH'] and IPAddress == self.defaultAddress:
                IPAddress = self.remoteResolve(packet.domain)
            UDPSocket.sendto(packet.buildReply(IPAddress), sourceAddress)
            chartdLogger.info('DNS reply sent to {0}: {1}[{2}]'.format(sourceAddress[0], packet.domain, IPAddress))


class DNSQuery(object):
    """A DNS Query packet"""

    def __init__(self, data):
        self.data   = data
        self.domain = ''
        tipo = (ord(data[2]) >> 3) & 15
        if tipo == 0:
            ini = 12
            lon = ord(data[ini])
            while lon != 0:
                self.domain += data[ini+1:ini+lon+1] + '.'
                ini += lon+1
                lon = ord(data[ini])

    def buildReply(self, ip):
        """Build a DNS reply packet"""

        packet = ''
        if ip == '':
            packet += self.data[:2]  + '\x81\x83'
            packet += self.data[4:6] + '\x00\x00' + '\x00\x00\x00\x00'
            packet += self.data[12:]

        if self.domain and packet == '':
            packet += self.data[:2]  + '\x81\x80'
            packet += self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'
            packet += self.data[12:]
            packet += '\xc0\x0c'
            packet += '\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'
            packet += str.join('', map(lambda x: chr(int(x)), ip.split('.')))

        return packet


def main():
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', metavar='FILE', action='store', help='Specify the configuration file to use')
    parser.add_argument('-z', '--zonefile', metavar='FILE', action='store', help='Specify the zone file to use')
    parser.add_argument('-d', '--default', metavar='IP', action='store', help='Set a default IP address for when domain can\'t be resolved')
    parser.add_argument('-n', '--noredis', action='store_true', default=True, help='Don\'t use Redis for zone file entries')
    parser.add_argument('-r', '--resolve', action='store_true', default=False, help='Attempt to resolve domain name over network if not found in local cache')
    args = parser.parse_args()
    """

    named = Chartd()
    named.loadConfiguration()
    named.loadZoneFile()
    named.mainloop()


if __name__ == '__main__':
    try:
        main()
    except(KeyboardInterrupt):
        UDPSocket.close()
