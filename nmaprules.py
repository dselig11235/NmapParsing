#!/usr/bin/python

import re

class Classifier:
    pass

rules = []
def rule(fn):
    rules.append(fn)
    return fn

def classifier(name):
    def classifier_as(fn):
        def fnRule(rec):
            if fn(rec):
                rec[4].append(name)
        rule(fnRule)
        return fn
    return classifier_as

@rule
def initialize(rec):
    rec.append([])

@classifier('dns')
def isDns(rec):
    return rec[2] == "domain" or rec[1].startswith('53/')

@classifier('ftp')
def isFtp(rec):
    return rec[1] == '21/tcp' or rec[2] == 'ftp'

@classifier('ssh')
def isSsh(rec):
    return rec[1] == '22/tcp' or rec[2] == 'ssh'

@classifier('telnet')
def isTelnet(rec):
    return rec[1] == '23/tcp'

@classifier('msrpc')
def isMSRPC(rec):
    return rec[2] == 'msrpc' or rec[1] == '135/tcp'

@classifier('nbt')
def isNBT(rec):
    return rec[1] == '139/tcp'

@classifier('smb')
def isNBT(rec):
    return rec[1] == '445/tcp'

@classifier('ldap')
def isLDAP(rec):
    return rec[1] == '389/tcp'

@classifier('vnc')
def isVNC(rec):
    return rec[2].startswith('vnc') or re.match('590\d/tcp', rec[1]) is not None

@classifier('ike')
def isIke(rec):
    return rec[1].startswith('500/')

@classifier('ntp')
def isNtp(rec):
    return rec[1].startswith('123/') or rec[2] == 'ntp'

@classifier('smtp')
def isSmtp(rec):
    return rec[1].startswith('25/') or 'smtp' in rec[2]

@classifier('snmp')
def isSnmp(rec):
    return rec[1].startswith('161/udp') or rec[2] == 'snmp'

@classifier('rdp')
def isSip(rec):
    return rec[1] == '3389/tcp'

@classifier('mssql')
def isSip(rec):
    return rec[1] == '1443/tcp'

@classifier('mysql')
def isSip(rec):
    return rec[1] == '3306/tcp'

@classifier('oracle')
def isSip(rec):
    return rec[1] == '1521/tcp'

@classifier('postgres')
def isSip(rec):
    return rec[1] == '5432/tcp'

@classifier('ssl')
def isSsl(rec):
    return 'ssl' in rec[2]

@classifier('http')
def isHttp(rec):
    return 'http' in rec[2] and not isSsl(rec)

@classifier('https')
def isHttps(rec):
    return 'http' in rec[2] and isSsl(rec)

@classifier('sip')
def isSip(rec):
    return 'sip' in rec[2]

@rule
def wrappedRule(rec):
    if rec[2] == 'tcpwrapped':
        rec[4] = ['nc']

@rule
def elseRule(rec):
    if len(rec[4])==0:
        rec[4] = ['unknown']

def classify(data):
    for rec in data:
        for rule in rules:
            rule(rec)

