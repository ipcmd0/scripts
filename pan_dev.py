#!/usr/bin/env python

from random import randrange
import random
import sys

def createPort():
	protocol = random.choice([ 'tcp', 'udp' ])
	port = str(randrange(1024, 2024, 1))
	socket = protocol + port
   	return socket;

def createAddr(ip):
        address = ip + str(randrange(1, 254,1))
        return address;

paTemplate = """                <entry name="%(ruleName)s">
                  <option>
                    <disable-server-response-inspection>no</disable-server-response-inspection>
                  </option>
                  <from>
                    <member>Untrust</member>
                  </from>
                  <to>
                    <member>Trust</member>
                  </to>
                  <source>
                    <member>%(sourceIP)s</member>
                  </source>
                  <destination>
                    <member>%(destIP)s</member>
                  </destination>
                  <source-user>
                    <member>any</member>
                  </source-user>
                  <category>
                    <member>any</member>
                  </category>
                    <member>any</member>
                  </application>
                  <service>
                    <member>%(service)s</member>
                  </service>
                  <hip-profiles>
                    <member>any</member>
                  </hip-profiles>
                  <log-start>no</log-start>
                  <log-end>yes</log-end>
                  <negate-source>no</negate-source>
                  <negate-destination>no</negate-destination>
                  <action>allow</action>
                </entry>
"""

if (len(sys.argv) == 2):
	policyMax = int(sys.argv[1])
	policyNum = 1

	file = open('rules.xml', 'w')

	file.write("""<?xml version="1.0"?>
<config version="4.1.0" urldb="brightcloud">
  <devices>
    <entry>
      <vsys>
        <entry>
	  <rulebase>
            <security>
              <rules>
""")

	while policyNum <= policyMax:
		src = createAddr('192.168.1.')
		dst = createAddr('172.16.10.')
        	protport = createPort()
	
		policy = {'ruleName':'policy-' + str(policyNum), 'sourceIP': src , 'destIP': dst , 'service': protport}
		file.write(paTemplate%policy)
		policyNum = policyNum + 1

	file.write("""              </rules>
            </security>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
""")

else:
        print """ Usage: pan_rule.py <policy#>

        Example: pan_rule.py 10
        """
