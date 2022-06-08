from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.node import OVSKernelSwitch, RemoteController
from time import sleep

from datetime import datetime
from random import randrange, choice

class MyTopo( Topo ):
    def build( self ):
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')

        h1 = self.addHost('h1', cpu=1.0/20, mac="00:00:00:00:00:01", ip="10.0.0.1/24")
        h2 = self.addHost('h2', cpu=1.0/20, mac="00:00:00:00:00:02", ip="10.0.0.2/24")
        h3 = self.addHost('h3', cpu=1.0/20, mac="00:00:00:00:00:03", ip="10.0.0.3/24")
        h4 = self.addHost('h4', cpu=1.0/20, mac="00:00:00:00:00:04", ip="10.0.0.4/24")

        # Add links

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)

def ip_generator():
    ip = ".".join(["10", "0", "0", str(randrange(1, 5))])
    return ip

def startNetwork():
    topo = MyTopo()

    c0 = RemoteController('c0', ip='192.168.1.6', port=6653)
    net = Mininet(topo=topo, link=TCLink, controller=c0)

    net.start()

    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')

    hosts = [h1, h2, h3, h4]

    #CLI( net )

    #sleep(60)

    for i in range(2):
        src = choice(hosts)
        dst = ip_generator()
        dst_str = hosts[int((dst.split('.'))[3]) - 1]
        while src == dst_str:
            dst = ip_generator()
            dst_str = hosts[int((dst.split('.'))[3]) - 1]

        print(dst_str)
        print(dst)
        print(src)
        #src.cmd("wireshark-gtk")
        #sleep(20)
        #dst_str.cmd("wireshark-gtk")
        #sleep(20)
        #print("ping from %s to h%s" % (src, ((dst.split('.'))[3])))
        print("ping from %s to %s" % (src, dst_str))
        src.sendCmd("timeout 20s ping {}".format(dst))
        sleep(40)
        #print("tcp traffic from %s to h%s" % (src, ((dst.split('.'))[3])))
        print("tcp traffic from %s to %s" % (src, dst_str))
        dst_str.sendCmd("iperf -s -p 5050 -t 21")
        sleep(0.5)
        src.sendCmd("iperf -p 5050 -c {} -t 20".format(dst))
        sleep(40)
        #print("udp traffic from %s to h%s" % (src, ((dst.split('.'))[3])))
        print("tcp traffic from %s to %s" % (src, dst_str))
        dst_str.sendCmd("iperf -s -u -p 5051 -t 21")
        sleep(0.5)
        src.sendCmd("iperf -p 5051 -u -c {} -t 20".format(dst))
        sleep(40)

    net.stop()

if __name__ == '__main__':

    start = datetime.now()

    setLogLevel( 'info' )
    startNetwork()

    end = datetime.now()

    print(end-start)
