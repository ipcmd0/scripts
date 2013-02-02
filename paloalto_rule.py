#!/usr/bin/env python

import xml.etree.ElementTree as xml
from xml.dom import minidom
import sys

#Creates the xml structure of a single policy
def policy_structure(nodes):
    root_node = xml.Element("entry")
    root_node.attrib['name'] = rulename

    for node in nodes:
        element = xml.SubElement(root_node, node)
        if node == "option":
            option = xml.SubElement(element, "disable-server-response-inspection")
            option.text = "no"
        if node == "profile-setting":
            group = xml.SubElement(element, "group")
            group.text = "Alert"
    
    return root_node

#function to populate the firewall rule with generic information
def member(base, node, attribute):
    for rulebase in base.findall(node):
        member = xml.SubElement(rulebase, "member")
        member.text = attribute
    return base

def policyentry(base, node, attribute):
    for rulebase in base.findall(node):
        rulebase.text = attribute
    return base

aclrules = open("access-list")

for line in aclrules:
    action, protocol, garbage, srczone, garbage, dstzone, srcip, garbage, dstip, port, garbage, description = line.split()

rulename = "rule1"
service = protocol + port

#lists used to feed data to the xml body structure
nodelist = ['option', 'from', 'to', 'source', 'destination', 'source-user', 'category', 'application', 'service', 'hip-profiles', 'log-start', 'log-end', 'log-setting', 'negate-source', 'negate-destination', 'action', 'profile-setting', 'description']

#xpathvalue = /config/devices/entry/vsys/entry/rulebase/security/rules/entry[@name=rulename]

memberentries = {"from":srczone, "to":dstzone, "source":srcip, "destination":dstip, "service":service, "source-user":"any", "category":"any", "application":"any", "hip-profiles":"any"}
policyentries = {"log-start":"no", "log-end":"yes", "negate-source":"no", "negate-destination":"no", "action":action, "description":description}

config = policy_structure(nodelist)

for key, value in memberentries.iteritems():
    config = member(config, key, value)

for key, value in policyentries.iteritems():
    config = policyentry(config, key, value)

print xml.tostring(config)

