#!/usr/bin/env python

import xml.etree.ElementTree as xml
from xml.dom import minidom
from random import randrange
import random
import sys

def createPort():
    protocol = random.choice([ 'tcp', 'udp' ])
    port = str(randrange(1024, 2024, 1))
    socket = protocol + port
    return socket

def createAddr(ip):
    address = ip + str(randrange(1, 254,1))
    return address

config = xml.Element('config')
devices = xml.Element('devices')
config.append(devices)
device_entry = xml.Element('entry')
devices.append(device_entry)
vsys = xml.Element('vsys')
device_entry.append(vsys)
vsys_entry = xml.Element('vsys')
device_entry.append(vsys_entry)
rulebase = xml.Element('rulebase')
vsys_entry.append(rulebase)
security = xml.Element('security')
rulebase.append(security)
rules = xml.Element('rules')
security.append(rules)

if (len(sys.argv) == 2):
    policyMax = int(sys.argv[1])
    policyNum = 1

    while policyNum <= policyMax:
        src = createAddr('192.168.1.')
        dst = createAddr('172.16.10.')
        protport = createPort()

        firewall_rule = xml.Element('entry')
        firewall_rule.attrib['name'] = ('policy-' + str(policyNum))
        rules.append(firewall_rule)
        option = xml.Element('option')
        firewall_rule.append(option)
        response_inspection = xml.Element('disable-server-response-inspection')
        option.append(response_inspection)
        from_zone = xml.Element('from')
        firewall_rule.append(from_zone)
        member_src_zone = xml.Element('member')
        from_zone.append(member_src_zone)
        to_zone = xml.Element('to')
        firewall_rule.append(to_zone)
        member_dst_zone = xml.Element('member')
        to_zone.append(member_dst_zone)
        source = xml.Element('source')
        firewall_rule.append(source)
        member_sourceIp = xml.Element('member')
        source.append(member_sourceIp)
        destination = xml.Element('destination')
        firewall_rule.append(destination)
        member_destIp = xml.Element('member')
        destination.append(member_destIp)
        source_user = xml.Element('source-user')
        firewall_rule.append(source_user)
        member_user = xml.Element('member')
        source_user.append(member_user)
        category = xml.Element('category')
        firewall_rule.append(category)
        member_cat = xml.Element('member')
        category.append(member_cat)
        application = xml.Element('application')
        firewall_rule.append(application)
        member_app = xml.Element('member')
        application.append(member_app)
        service = xml.Element('service')
        firewall_rule.append(service)
        member_service = xml.Element('member')
        service.append(member_service)
        hip_profiles = xml.Element('hip-profiles')
        firewall_rule.append(hip_profiles)
        member_hip = xml.Element('member')
        hip_profiles.append(member_hip)
        log_start = xml.Element('log-start')
        firewall_rule.append(log_start)
        log_end = xml.Element('log-end')
        firewall_rule.append(log_end)
        negate_source = xml.Element('negate-source')
        firewall_rule.append(negate_source)
        negate_destination = xml.Element('negate-destination')
        firewall_rule.append(negate_destination)
        action = xml.Element('action')
        firewall_rule.append(action)
        
        member_src_zone.text = "Untrust"
        member_dst_zone.text = "Trust" 
        member_sourceIp.text = src
        member_destIp.text = dst
        member_user.text = "any"
        member_cat.text = "any"
        member_app.text = "any"
        member_service.text = protport
        member_hip.text = "any"
        response_inspection.text = "no"
        log_start.text = "no"
        log_end.text = "yes"
        negate_source.text = "no"
        action.text = "allow"

        policyNum = policyNum + 1
        
print minidom.parseString(xml.tostring(config)).toprettyxml(indent = "   ")
