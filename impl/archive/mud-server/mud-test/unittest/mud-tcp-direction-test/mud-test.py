
from mininet.node import OVSController
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo
import pdb
import subprocess
import argparse
import os
import sys
import signal
from distutils.spawn import find_executable
from subprocess import call
import time
import requests
import json
from mininet.log import setLogLevel 
import unittest
import re
import os
import signal



#########################################################

global hosts

hosts = []

global failCount
failCount = 0

class TestAccess(unittest.TestCase) :
    
    def __init__(self,methodName):
        unittest.TestCase.__init__(self,methodName)
        print "TestAccess init " + methodName
        self.ntries = 7
        

    def setUp(self):
        pass

    def tearDown(self):
        pass
        

    def testTcpGetFromDeviceExpectSuccess(self):
        #inbound on port 8000 is allowed
        h4 = hosts[3]
        result = None
        result = h4.cmdPrint("wget 10.0.0.1:8000 --tries 2 --delete-after --timeout 20")
        self.assertTrue(re.search("100%",result) is not None, "Expecting a successful get : " + result)

    def testTcpGetFromDeviceExpectFail(self):
        #inbound on 800 is disallowed
        h5 = hosts[4]
        result = h4.cmdPrint("wget 10.0.0.1:800 --tries 2 --delete-after --timeout 10")
        self.assertTrue(re.search("100%",result) is None, "Expecting a failed get")

    def testDeviceTcpGetFromLocalNetworkExpectFail(self):
        #outbound on port 8000 is disallowed
        h1 = hosts[0]
        result = h1.cmdPrint("wget 10.0.0.3:8000 --tries 2 --delete-after --timeout 10")
        self.assertTrue(re.search("100%",result) is None, "Expecting a failed get")

    def testDeviceTcpGetFromLocalNetworkExpectPass(self):
        #inbound on 800 is allowed
        h1 = hosts[0]
        result = h1.cmdPrint("wget 10.0.0.3:800 --tries 2 --delete-after --timeout 10")
        self.assertTrue(re.search("100%",result) is not None, "Expecting a failed get")


    def tearDown(self):
        time.sleep(5)

#########################################################



def cli():
    global net,c1,s1,s2,s3
    global hosts
    cli = CLI( net )
    for h in hosts:
        h.terminate()
    net.stop()


def setupTopology(controller_addr):
    global net,c1,s1,s2,s3
    global h1,h2,h3,h4,h5,h6,h7,h8,h9,h10
    "Create and run multiple link network"

    net = Mininet(controller=RemoteController)

    print "mininet created"

    c1 = net.addController('c1', ip=controller_addr,port=6653)


    # h1: IOT Device.
    # h2 : StatciDHCPD
    # h3 : router / NAT
    # h4 : Non IOT device.

    h1 = net.addHost('h1')
    h2 = net.addHost('h2')
    h3 = net.addHost('h3')
    h4 = net.addHost('h4')
    h5 = net.addHost('h5')
    h6 = net.addHost('h6')
    h7 = net.addHost('h7')
    h8 = net.addHost('h8')
    h9 = net.addHost('h9')
    h10 = net.addHost('h10')

    hosts.append(h1)
    hosts.append(h2)
    hosts.append(h3)
    hosts.append(h4)
    hosts.append(h5)
    hosts.append(h6)
    hosts.append(h7)
    hosts.append(h8)
    hosts.append(h9)
    hosts.append(h10)

    s2 = net.addSwitch('s2',dpid="2")
    s3 = net.addSwitch('s3',dpid="3")
    s1 = net.addSwitch('s1',dpid="1")

    s1.linkTo(h1)
    s1.linkTo(h2)
    s1.linkTo(h3)
    s1.linkTo(h4)
    s1.linkTo(h5)
    s1.linkTo(h6)
    s1.linkTo(h7)

    s2.linkTo(h8)
    s3.linkTo(h8)

    s3.linkTo(h9)
    s3.linkTo(h10)

    # S2 is the NPE switch.
    # Direct link between S1 and S2
    s1.linkTo(s2)


    h8.cmdPrint('echo 0 > /proc/sys/net/ipv4/ip_forward')
    # Flush old rules.
    h8.cmdPrint('iptables -F')
    h8.cmdPrint('iptables -t nat -F')
    h8.cmdPrint('iptables -t mangle -F')
    h8.cmdPrint('iptables -X')
    h8.cmdPrint('echo 1 > /proc/sys/net/ipv4/ip_forward')

    # Set up h3 to be our router (it has two interfaces).
    # Set up iptables to forward as NAT
    h8.cmdPrint('iptables -t nat -A POSTROUTING -o h8-eth1 -s 10.0.0.0/24 -j MASQUERADE')

    net.build()
    net.build()
    c1.start()
    s1.start([c1])
    s2.start([c1])
    s3.start([c1])

    net.start()
     

    # Clean up any traces of the previous invocation (for safety)


    h1.setMAC("00:00:00:00:00:41","h1-eth0")
    h2.setMAC("00:00:00:00:00:42","h2-eth0")
    h3.setMAC("00:00:00:00:00:43","h3-eth0")
    h4.setMAC("00:00:00:00:00:44","h4-eth0")
    h5.setMAC("00:00:00:00:00:45","h5-eth0")
    h6.setMAC("00:00:00:00:00:46","h6-eth0")
    h7.setMAC("00:00:00:00:00:47","h7-eth0")
    h8.setMAC("00:00:00:00:00:48","h8-eth0")
    h9.setMAC("00:00:00:00:00:49","h9-eth0")
    h10.setMAC("00:00:00:00:00:4A","h10-eth0")

    
    # Set up a routing rule on h2 to route packets via h3
    h1.cmdPrint('ip route del default')
    h1.cmdPrint('ip route add default via 10.0.0.8 dev h1-eth0')

    # Set up a routing rule on h2 to route packets via h3
    h2.cmdPrint('ip route del default')
    h2.cmdPrint('ip route add default via 10.0.0.8 dev h2-eth0')

    # Set up a routing rule on h2 to route packets via h7
    h3.cmdPrint('ip route del default')
    h3.cmdPrint('ip route add default via 10.0.0.8 dev h3-eth0')

    # Set up a routing rule on h2 to route packets via h3
    h4.cmdPrint('ip route del default')
    h4.cmdPrint('ip route add default via 10.0.0.8 dev h4-eth0')

    # Set up a routing rule on h5 to route packets via h3
    h5.cmdPrint('ip route del default')
    h5.cmdPrint('ip route add default via 10.0.0.8 dev h5-eth0')

    # h6 is a localhost.
    h6.cmdPrint('ip route del default')
    h6.cmdPrint('ip route add default via 10.0.0.8 dev h6-eth0')

    # The IDS runs on h8
    h7.cmdPrint('ip route del default')
    h7.cmdPrint('ip route add default via 10.0.0.8 dev h7-eth0')

    # h9 is our fake host. It runs our "internet" web server.
    h9.cmdPrint('ifconfig h9-eth0 203.0.113.13 netmask 255.255.255.0')
    # Start a web server there.

    # h10 is our second fake host. It runs another internet web server that we cannot reach
    h10.cmdPrint('ifconfig h10-eth0 203.0.113.14 netmask 255.255.255.0')


    # Start dnsmasq (our dns server).
    h5.cmdPrint('/usr/sbin/dnsmasq --server  10.0.4.3 --pid-file=/tmp/dnsmasq.pid'  )

    # Set up our router routes.
    h8.cmdPrint('ip route add 203.0.113.13/32 dev h8-eth1')
    h8.cmdPrint('ip route add 203.0.113.14/32 dev h8-eth1')
    h8.cmdPrint('ifconfig h8-eth1 203.0.113.1 netmask 255.255.255.0')
    

    #subprocess.Popen(cmd,shell=True,  stdin= subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=False)
    h3.cmdPrint("python -m SimpleHTTPServer 8000&")
    h1.cmdPrint("python -m SimpleHTTPServer 8000&")
    h4.cmdPrint("python -m SimpleHTTPServer 8000&")
    h1.cmdPrint("python -m SimpleHTTPServer 800&")
    h3.cmdPrint("python -m SimpleHTTPServer 800&")
    h5.cmdPrint("python -m SimpleHTTPServer 800&")
    

    net.waitConnected()

    print "*********** System ready *********"

    return net

def fixupResolvConf():
    # prepending 10.0.0.5 -- we want to go through our name resolution
    found = False
    with open("/etc/resolv.conf") as f :
	content = f.readlines() 
        found = False
        for line in content:
	    if line.find("10.0.0.5") != -1:
		found = True
		break

    print("10.0.0.5 not found in resolv.conf")
    if not found :
        original_data = None
        with open("/etc/resolv.conf") as f :
	    original_data = f.read()
	with open("/etc/resolv.conf.save","w") as f:
	     f.write(original_data)
	with open("/etc/resolv.conf","w") as f:
	     f.write("nameserver 10.0.0.5\n" + original_data)

def startTestServer(host):
    """
    Start a test server to add to the allow access rules.
    """
    os.chdir("%s/mininet/testserver" % IOT_MUD_HOME)
    cmd = "/usr/bin/xterm -e \"/usr/bin/python testserver.py -H %s;bash\"" % host
    print cmd
    proc = subprocess.Popen(cmd,shell=True, stdin= subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)  
    print "test server started"

if __name__ == '__main__':
    setLogLevel( 'info' )
    parser = argparse.ArgumentParser()
    # defaults to the address assigned to my VM
    parser.add_argument("-c",help="Controller host address",default=os.environ.get("CONTROLLER_ADDR"))
    parser.add_argument("-d",help="Public DNS address (check your resolv.conf)",default="10.0.4.3")
    parser.add_argument("-f",help="Config file",default="sdnmud-config.json")

    parser.set_defaults(test=False)

    args = parser.parse_args()
    controller_addr = args.c
    test = args.test
    cfgfile = args.f

    cmd = ['sudo','mn','-c']
    proc = subprocess.Popen(cmd,shell=False, stdin= subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.wait()
    
    cmd = ['sudo','pkill','dnsmasq']
    proc = subprocess.Popen(cmd,shell=False, stdin= subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.wait()

    # Pkill dnsmasq. We will start one up later on h3
    if os.path.exists("/tmp/dnsmasq.pid"):
    	f = open('/tmp/dnsmasq.pid')
    	pid = int(f.readline())
    	try:
    	   os.kill(pid,signal.SIGTERM)
	except:
	   print "Failed to kill dnsmasq check if process is running"


    print("IMPORTANT : append 10.0.0.5 to resolv.conf")
    fixupResolvConf()
    net = setupTopology(controller_addr)

    headers= {"Content-Type":"application/json"}
    for (configfile,suffix) in {
        ("device-association-toaster.json","nist-mud-device-association:mapping"),
        ("controllerclass-mapping.json","nist-mud-controllerclass-mapping:controllerclass-mapping"),
        (cfgfile, "sdnmud:sdnmud-config") } :
        print "configfile", configfile
        data = json.load(open(configfile))
        url = "http://" + controller_addr + ":8181/restconf/config/" + suffix
        print "url ", url
        r = requests.put(url, data=json.dumps(data), headers=headers , auth=('admin', 'admin'))
        print "response ", r

    net.pingAll(1)
    h1.cmdPrint("nslookup www.nist.local")
    h1.cmdPrint("nslookup www.antd.local")


    if os.environ.get("UNITTEST") is not None and os.environ.get("UNITTEST") == '1' :
        unittest.main()
    else:
        cli()
