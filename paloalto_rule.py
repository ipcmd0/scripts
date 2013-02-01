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
        if node == "profile-setting":
            group = xml.SubElement(element, "group")

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

#lists used to feed data to the xml body structure
nodelist = ['option', 'from', 'to', 'source', 'destination', 'source-user', 'category', 'application', 'service', 'hip-profiles', 'log-start', 'log-end', 'log-setting', 'negate-source', 'negate-destination', 'action', 'profile-setting', 'description']



#Generic variables for testing, will be replaced with input from file information
rulename = "rule1"
srcip = "1.1.1.1"
dstip = "2.2.2.2"
action = "allow"
service = "tcp8080"
description = "test"
srczone = "Trust"
dstzone = "Untrust"
description = "testing"

#xpathvalue = /config/devices/entry/vsys/entry/rulebase/security/rules/entry[@name=rulename]

config = policy_structure(nodelist)

memberentries = {"from":srczone, "to":dstzone, "source":srcip, "destination":dstip, "service":service, "source-user":"any", "category":"any", "application":"any", "hip-profiles":"any"}

policyentries = {"log-start":"no", "log-end":"yes", "negate-source":"no", "negate-destination":"no", "disable-server-response-inspection":"no", "action":action, "description":description, "group":"profile"}

for key, value in memberentries.iteritems():
    config = member(config, key, value)

for key, value in policyentries.iteritems():
    config = policyentry(config, key, value)

print xml.tostring(config)
