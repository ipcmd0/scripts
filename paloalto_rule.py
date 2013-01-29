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
        element = xml.Element(node)
        parent_node.append(element)
        parent_node = element
    
    return root_node

def add_policy(base, nodes):
    for rulebase in  base.findall(".//rules"):
        entry = xml.Element("entry")
        rulebase.append(entry)

        for node in nodes:
            element = xml.Element(node)
            entry.append(element)
            if node == "option":
                option = xml.SubElement(element, "disable-server-response-inspection")
            if node == "profile-setting":
                profile = xml.SubElement(element, "profiles")
                addurl = xml.SubElement(profile, "url-filtering")
                addfileblock = xml.SubElement(profile, "url-filtering")
                addvirus = xml.SubElement(profile, "virus")
                addspy = xml.SubElement(profile, "spyware")
                addvuln = xml.SubElement(profile, "vulnerability")

    return base

nodelist = ['config', 'devices', 'entry', 'vsys', 'entry', 'rulebase', 'security', 'rules'] 
policylist = ['option', 'from', 'to', 'source', 'destination', 'source-user', 'category', 'application', 'service', 'hip-profiles', 'log-start', 'log-end', 'log-setting', 'negate-source', 'negate-destination', 'action', 'profile-setting']

config = make_tree(nodelist)
config = add_policy(config, policylist)

print minidom.parseString(xml.tostring(config)).toprettyxml(indent = "   ")
