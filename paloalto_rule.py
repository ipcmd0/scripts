#!/usr/bin/env python

import xml.etree.ElementTree as xml
from xml.etree import ElementTree
from xml.dom import minidom
import sys

# Function that creates the base structure of the xml file
def make_tree(nodes):
    root_node = xml.Element(nodes.pop(0))
    parent_node = root_node

    for node in nodes:
        element = xml.SubElement(parent_node, node)
        parent_node = element
    return root_node

#Creates the xml structure of a single policy
def policy_structure(base, nodes):
    for rulebase in base.findall(".//rules"):
        entry = xml.SubElement(rulebase, "entry")

        for node in nodes:
            element = xml.SubElement(entry, node)

            if node == "option":
                option = xml.SubElement(element, "disable-server-response-inspection")
                option.text = "no"
            if node == "profile-setting":
                profile = xml.SubElement(element, "profiles")
                for item in profilelist:
                    addprofile = xml.SubElement(profile, item)
    return base

#function to name firewall rule
def rule(base, name):
    for rulebase in base.findall('.//rules/entry'):
        rulebase.attrib['name'] = name
    return base

#function to populate the firewall rule with generic information
def definepolicy(base, node, text):
    for rulebase in base.findall(".//rules/entry/" + node):
        member = xml.SubElement(rulebase, "member")
        member.text = text
    return base

#lists used to feed data to the xml body structure
nodelist = ['config', 'devices', 'entry', 'vsys', 'entry', 'rulebase', 'security', 'rules'] 
policylist = ['option', 'from', 'to', 'source', 'destination', 'source-user', 'category', 'application', 'service', 'hip-profiles', 'log-start', 'log-end', 'log-setting', 'negate-source', 'negate-destination', 'action', 'profile-setting']
profilelist = ['url-filtering', 'file-blocking', 'virus', 'spyware', 'vulnerability']
genericsettings = ['source-user', 'category', 'application', 'hip-profiles']

config = make_tree(nodelist)
config = policy_structure(config, policylist)
config = rule(config, "test")
config = definepolicy(config, "from", "Untrust")
config = definepolicy(config, "to", "Trust")
for item in genericsettings:
    config = definepolicy(config, item, "any")

print minidom.parseString(xml.tostring(config)).toprettyxml(indent = "   ")
