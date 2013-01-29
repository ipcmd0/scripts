#!/usr/bin/env python

import xml.etree.ElementTree as xml
from xml.etree import ElementTree
from xml.dom import minidom
from random import randrange
import random
import sys

def create_port():
    protocol = random.choice([ 'tcp', 'udp' ])
    port = str(randrange(1024, 2024, 1))
    socket = protocol + port
    return socket

def create_ddr(ip):
    address = ip + str(randrange(1, 254,1))
    return address

def make_tree(nodes):
    root_node = xml.Element(nodes.pop(0))
    parent_node = root_node

    for node in nodes:
        element = xml.SubElement(parent_node, node)
        parent_node = element
    return root_node

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

def rule(base):
    for rulebase in base.findall(".//rules/entry"):
        rulebase.attrib['name'] = "test"
    return base


nodelist = ['config', 'devices', 'entry', 'vsys', 'entry', 'rulebase', 'security', 'rules'] 
policylist = ['option', 'from', 'to', 'source', 'destination', 'source-user', 'category', 'application', 'service', 'hip-profiles', 'log-start', 'log-end', 'log-setting', 'negate-source', 'negate-destination', 'action', 'profile-setting']
profilelist = ['url-filtering', 'file-blocking', 'virus', 'spyware', 'vulnerability']

config = make_tree(nodelist)
config = policy_structure(config, policylist)
config = rule(config)

print minidom.parseString(xml.tostring(config)).toprettyxml(indent = "   ")
