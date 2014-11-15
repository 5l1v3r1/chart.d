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
import redis
import socket
import os.path
import logging
import argparse

# I still haven't fixed this? Jesus fuck man....
packtdLogger = logging.getLogger('Pequod.chartd')  # Rename to chartdLogger Lol :P
packtdLogger.setLevel(logging.INFO)
try:
    socket.SO_REUSEPORT
except(AttributeError):
    socket.SO_REUSEPORT = 15


class Chartd(object):
    """Tiny host(A) record DNS server"""

    def __init__(self, defaultAddress='127.0.0.1', useRedis=False, redisAddress='localhost'):
        self.defaultAddress = defaultAddress
        self.useRedis       = useRedis
        self.redisAddress   = redisAddress
        self.zoneRecords    = {}
        self.configuration  = {}

    def loadConfiguration(self, configuration):
        """Load a configuration file in to self.configuration"""

        packtdLogger.debug('Attempting to load configuration file {0}'.format(configuration))
        if not os.path.isfile(configration):
            packtdLogger.error('Could not find {0}: Does not exist'.format(configuration))
            raise IOError('Configuration file \'{0}\' not found'.format(configuration))

        with open(configuration, 'r') as config:
            configContent = config.read()
            try:
                configuration = json.loads(configContent)
                packtdLogger.info('Succesfully loaded configuration file {0}'.format(configuration))
            except():  # What is the exception it needs to catch?
                configuration = {}
                packtdLogger.error('Could not properly read configuration file {0}: JSON SyntaxError'.format(configuration))
            finally:
                self.configuration = configuration

        return self.configuration

    def loadZoneFile(self, zoneFile):
        """Load a JSON zone file in to memory"""

        packtdLogger.debug('Attempting to load zone file {0}'.format(zoneFile))
        if self.useRedis:
            # Read a zone file in to Redis DB
            pass
        else:
            if not os.path.isfile(zoneFile):
                packtdLogger.error('Could not find {0}: Doesnot exist'.format(zoneFile))
                raise IOError('Zone file \'{0}\' not found'.format(zoneFile))

            with open(zoneFile, 'r') as f:
                zoneContent = f.read()
                try:
                    zoneRecords = json.loads(zoneContent)
                    packtdLogger.info('Succesfully loaded configuratioin file {0}'.format(zoneFile))
                except():
                    zoneRecords = {}
                    packtdLogger.error('Could not properly read zone file {0}: JSON SyntaxError'.format(zoneFile))
                finally:
                    self.zoneRecords = zoneRecords

            return self.zoneRecords

    def remoteResolve(self, domain):
        """Attempt to resolve a domain using socket.gethostname()"""

        try:
            IPAddress = socket.gethostbyname(domain)
            packtdLogger.info('Translated: {0} <-> [{1}]'.format(domain, IPAddress))
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
        packtdLogger.debug('Attempting to resolve domain {0} locally'.format(doamin))

        if useRedis:
            try:
                pass
                # Need to revisit with more Redis and python driver knowledge
                #redisServer = redis.Redis(self.redisAddress)
                #ARecord = redisServer.hget('chartd.domains', domain)
                #redisServer.close()
            except:
                packtdLogger.warning('No connection with redis server [{0}]'.format(self.redisAddress))
                ARecord = self.defaultAddress

            if ARecord is not None:
                packtdLogger.info('Translated: {0} <-> [{1}]'.format(domain, ARecord))
                return ARecord
            else:
                packtdLogger.warning('Entry for domain {0} not found in database'.format(domain))
                return self.defaultAddress

        else:
            if domain in self.zoneRecords.keys():
                packtdLogger.info('Host {0} found in local cache'.format())
                return self.zoneRecords[domain]
            else:
                packtdLogger.warning('Entry for domain {0} not found in cache'.format(domain))
                return defaultAddress

    def mainloop(self):
        """Start chart.d daemon and bind to port"""

        packtdLogger.info('Starting chart.d under PID: {0}'.format(os.getpid()))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as UDPSocket:
            try:
                UDPSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except(socket.error):  # Swallowing errors is fun :D
                packtdLogger.error('SO_REUSEPORT not supported by this system')
            UDPSocket.bind(('', 53))

            while True:
                IPAddress = ''
                data, sourceAddress = UDPSocket.recvfrom(1024)
                packet = DNSQuery(data)
                IPAddress = localResolve(packet.domain)
                # If our localResolve failed and fell back to our default address
                if self.configuration['FORWARD_NOMATCH'] and IPAddress == self.defaultAddress:
                    IPAddress = remoteResolve(packet.domain)
                UDPSocket.sendto(packet.buildReply(IPAddress), sourceAddress)
                packtdLogger.info('DNS reply sent to {0}: {1}[{2}]'.format(sourceAddress[0], packet.domain, IPAddress)


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
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', metavar='FILE', action='store', help='Specify the configuration file to use')
    parser.add_argument('-z', '--zonefile', metavar='FILE', action='store', help='Specify the zone file to use')
    parser.add_argument('-d', '--default', metavar='IP', action='store', help='Set a default IP address for when domain can\'t be resolved')
    parser.add_argument('-n', '--noredis', action='store_true', default=True, help='Don\'t use Redis for zone file entries')
    parser.add_argument('-r', '--resolve', action='store_true', default=False, help='Attempt to resolve domain name over network if not found in local cache')
    args = parser.parse_args()

    print('Sweet Jesus what in god\'s name are you doin son?!')
    sys.exit(127)  # Because there's no sys.kernelpanic() method :(
    # Note to self, write a sys.kernelpanic method. You're welcome Guido...

if __name__ == '__main__':
    try:
        main()
    except(KeyboardInterrupt):
        print()
