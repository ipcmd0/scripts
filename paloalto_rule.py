#!/usr/bin/env python

import xml.etree.ElementTree as xml
from xml.dom import minidom
import sys

#Creates the xml structure of a single policy
def policy_structure(nodes):
    root_node = xml.Element("root")
    root_node.attrib['name'] = rulename

    for node in nodes:
        element = xml.SubElement(root_node, node)
        if node == "option":
            option = xml.SubElement(element, "disable-server-response-inspection")
        if node == "profile-setting":
            group = xml.SubElement(element, "group")

    return root_node

#function to populate the firewall rule with generic information
def definepolicy(base, node, text):
    for rulebase in base.findall(".//" + node):
        member = xml.SubElement(rulebase, "member")
        member.text = text
    return base

#lists used to feed data to the xml body structure
nodelist = ['option', 'from', 'to', 'source', 'destination', 'source-user', 'category', 'application', 'service', 'hip-profiles', 'log-start', 'log-end', 'log-setting', 'negate-source', 'negate-destination', 'action', 'profile-setting', 'description']
genericsettings = ['source-user', 'category', 'application', 'hip-profiles']



#Generic variables for testing, will be replaced with input from file information
rulename = "test"
srcip = "1.1.1.1"
dstip = "2.2.2.2"
action = "allow"
service = "tcp8080"
description = "test"
srczone = "Trust"
dstzone = "Untrust"

#xpathvalue = /config/devices/entry/vsys/entry/rulebase/security/rules/entry[@name=rulename]

config = policy_structure(nodelist)
#config = rule(config, name)

#dynamic information
config = definepolicy(config, "from", "Untrust")
config = definepolicy(config, "to", "Trust")
config = definepolicy(config, "source", srcip)
config = definepolicy(config, "destination", dstip)
config = definepolicy(config, "action", action)
config = definepolicy(config, "service", service)

#static information, see if can be replaced with a key/list
config = definepolicy(config, "log-start", "no")
config = definepolicy(config, "log-end", "yes")
config = definepolicy(config, "negate-source", "no")
config = definepolicy(config, "negate-destination", "no")

for item in genericsettings:
    config = definepolicy(config, item, "any")

print xml.tostring(config)
