import requests
import ast
import socket
import threading
import networkx as nx
import matplotlib.pyplot as plt
import sys
links_stats={}
flowDB = {}
arp_table = {}
hosts = []
serversock=''

controllerip = '199.165.75.182'

def tcpconnect(controllerip):
    global serversock
    global arp_table
    global hosts
    global flowDB
    serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (controllerip, 8443)
    try:
        serversock.connect(server_address)
        print "connection with the application client established"
        data = serversock.recv(4096)
        if data:
            print "updating flow DB and arp_table"
            flowDB,arp_table = map(ast.literal_eval,data.split('%'))
            print "data",data

    except:
        print "connection to the application client failed exiting"
        serversock=''


def hostDiscovery():
    global serversock
    print serversock
    global flowDB
    global arp_table
    while(1):
        try:
            data = serversock.recv(4096)
            
            if '%' in data:
                flowDB,arp_table = map(ast.literal_eval,data.split('%'))
                print "first update flowdb and arptable"
                print flowDB
                print arp_table
                continue
            if '#' in data:
                print "updating flow DB " 
                flowDB = ast.literal_eval(data.split('#')[1])
                print "--------------------------------------------------------"
                print flowDB
                print "--------------------------------------------------------"
                continue
            switch,host,port = data.split(',')
            print "Received Host ARP"
            print "--------------------------------------------------------"
            print data
            print "--------------------------------------------------------"
            if switch not in arp_table:
                arp_table[switch]={}

            if host not in arp_table[switch]:
                arp_table[switch][host]=port
                hosts.append(host)
                print "Updated HOST table "
                print "--------------------------------------------------------"
                print "host discovered ",hosts
                for switch,value in arp_table.iteritems():
                    print switch,value
                print "--------------------------------------------------------"
        except:
            pass



def topologyviewer():
    build_link_stats(controllerip)
    G = nx.Graph()
    
    for switch in links_stats:
        G.add_node(switch)
        for i in links_stats[switch]:
            G.add_edge(switch,i)
    for switch in arp_table:
        for i in arp_table[switch]:
            G.add_edge(switch,i)
    
 
    nx.draw(G,with_labels=True)
    plt.savefig("topology.png")
    plt.show()


def build_link_stats(controller_ip):
    links = requests.get('http://'+controller_ip+':8080/v1.0/topology/links')
    links = ast.literal_eval(links.text)
    for link in links:
        if link['src']['dpid'] not in links_stats:
            links_stats[link['src']['dpid']] = {}
            links_stats[link['src']['dpid']][link['dst']['dpid']] = link['src']['port_no']
        else:
            links_stats[link['src']['dpid']][link['dst']['dpid']] = link['src']['port_no']

    for key,value in links_stats.iteritems():
        print key,value

def get_flow(switchlist,dstip):
    flow=[]
    if len(switchlist) > len(arp_table):
        print "cannot construct a flow"
        return flow
    global links_stats
    for switch in switchlist:
        if switch not in links_stats:
            return flow
    prev = links_stats[switchlist[0]]
    prev_switch = switchlist[0]
    
    for switch in switchlist[1:]:
        if switch in prev:
            flow.append((prev_switch,prev[switch]))
        prev = links_stats[switch]
        prev_switch=switch
    if dstip in arp_table[prev_switch]:
        flow.append((prev_switch,arp_table[prev_switch][dstip]))
    return flow

def pushflowDB():
    global serversock
    try:
        print "sending updated DB"
        serversock.send(str(flowDB))
    except:
        print "flow DB update failed to send"

def deletearpflow(flow,dstip):
    for dpid in flow:
        r = requests.post('http://'+controllerip+':8080/stats/flowentry/delete',data='{"dpid":"'+str('0x'+dpid[4:])+'","table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 2,"flags": 1,"match":{"eth_type":0x806,"nw_dst":"'+str(dstip)+'"},"actions":[]}')
        print "removing arp flow"
        print 'http://'+controllerip+':8080/stats/flowentry/delete data={"dpid":"'+str('0x'+dpid[4:])+'","table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 2,"flags": 1,"match":{"eth_type":0x806,"nw_dst":"'+str(dstip)+'"},"actions":[]}'
        if r.status_code == requests.codes.ok:
            print "successfully removed flow in the switch"
        else:
            print "failed removing flow"

def deleteicmpflow(flow,dstip):
    for dpid in flow:
        r = requests.post('http://'+controllerip+':8080/stats/flowentry/delete',data='{"dpid":"'+str('0x'+dpid[4:])+'","table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 2,"flags": 1,"match":{"eth_type":0x800,"nw_dst":"'+str(dstip)+'","ip_proto":1},"actions":[]}')
        print "removing icmp flow"
        print 'http://'+controllerip+':8080/stats/flowentry/delete data={"dpid":"'+str('0x'+dpid[4:])+'","table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 2,"flags": 1,"match":{"eth_type":0x800,"nw_dst":"'+str(dstip)+'","ip_proto":1},"actions":[]}'
        if r.status_code == requests.codes.ok:
            print "successfully removed icmp flow in the switch"
        else:
            print "failed removing icmp flow"

def deletetcpudpflow(flow,srcip,dstip,tcpudp,port):
    if 'tcp' in tcpudp:
        ipproto = 6
    else:
        ipproto = 17
    for dpid in flow:
        r = requests.post('http://'+controllerip+':8080/stats/flowentry/delete',data='{"dpid":"'+str('0x'+dpid[4:])+'","table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 2,"flags": 1,"match":{"eth_type":0x0800,"nw_dst":"'+str(dstip)+'","ip_proto":'+ipproto+','+tcpudp+':"'+str(port)+'"},"actions":[]}')
        print "tcp flow mod for switch"
        print 'http://'+controllerip+'8080/stats/flowentry/delete,data={"dpid":"'+str('0x'+dpid[4:])+'","table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 2,"flags": 1,"match":{"eth_type":0x0800,"nw_dst":"'+str(dstip)+'","ip_proto":'+ipproto+','+tcpudp+':"'+str(port)+'"},"actions":[]}'
        if r.status_code == requests.codes.ok:
            print "successfully removed tcp flow in the switch"
        else:
            print "failed removing flow "


def build_flowDB(srcip,dstip,port,tcp_udp,switches):
    global flowDB
    flow = get_flow(switches,dstip)
    if len(flow) != len(switches):
        print "Could not form a flow with the switches please retry"
        return []
    if srcip not in flowDB:
#	source ip not present totally new entry !!
        print "source ip not present adding a new entry"
        flowDB[srcip] = {}
        flowDB[srcip][dstip] = {}
        flow = get_flow(switches,dstip)
        flowDB[srcip][dstip] = {}
        flowDB[srcip][dstip]['arp'] = {}
        flowDB[srcip][dstip]['icmp'] = {}
        flowDB[srcip][dstip]['icmp']['default'] = [flow,'install']
        flowDB[srcip][dstip]['arp']['default'] = [flow,'install']
        flowDB[srcip][dstip][tcp_udp] = {}
        flowDB[srcip][dstip][tcp_udp][port] = [flow,'install']


    else:

        if dstip not in flowDB[srcip]:
#	source ip present but not destination ip new entry again !!
            print "source ip not present but not destination adding a new entry"
            flowDB[srcip][dstip]={}
            flow = get_flow(switches,dstip)
            flowDB[srcip][dstip]['arp'] = {}
            flowDB[srcip][dstip]['icmp'] = {}
            flowDB[srcip][dstip]['icmp']['default'] = [flow,'install']
            flowDB[srcip][dstip]['arp']['default'] = [flow,'install']
            flowDB[srcip][dstip][tcp_udp] = {}
            flowDB[srcip][dstip][tcp_udp][port] = [flow,'install']

        else:

#       source ip present and destination ip present
#         1) look for old arp and icmp entries
#         2) if they exist and marked as dropped  delete the flow entries in all the switches and then overwrite
#	      3) if they exist and marked as installed?? overwrite, tcp connections will happen in the newroute but arp,ping in old route


            if tcp_udp not in flowDB[srcip][dstip]:#		no definition for tcp_udp overwrite the existing old entries for arp and icmp between those srcip and dst ip

                if 'arp' in flowDB[srcip][dstip]:
                    if flowDB[srcip][dstip]['arp']['default'][1] == 'dropped':
                        print "srcip and dstip present arp status dropped"
                        deletearpflow(flowDB[srcip][dstip]['arp']['default'][0],dstip)
                        flow = get_flow(switches,dstip)
                        flowDB[srcip][dstip]['arp'] = {}
                        flowDB[srcip][dstip]['arp']['default'] = [flow,'install']
                        flowDB[srcip][dstip][tcp_udp] = {}
                        flowDB[srcip][dstip][tcp_udp][port] = [flow,'install']

                    else:
                        print "srcip and dstip present arp status not dropped overwriting old entries"
                        flow = get_flow(switches,dstip)
                        flowDB[srcip][dstip]['arp'] = {}
                        flowDB[srcip][dstip]['arp']['default'] = [flow,'install']
                        flowDB[srcip][dstip][tcp_udp] = {}
                        flowDB[srcip][dstip][tcp_udp][port] = [flow,'install']

                else:
                    print "srcip and dstip present arp found"
                    flow = get_flow(switches,dstip)
                    flowDB[srcip][dstip]['arp'] = {}
                    flowDB[srcip][dstip]['arp']['default'] = [flow,'install']
                    flowDB[srcip][dstip][tcp_udp] = {}
                    flowDB[srcip][dstip][tcp_udp][port] = [flow,'install']


                if 'icmp' in flowDB[srcip][dstip]:
                    if flowDB[srcip][dstip]['icmp']['default'][1] == 'dropped':
                        print "srcip and dstip present icmp status dropped"
                        deleteicmpflow(flowDB[srcip][dstip]['icmp']['default'][0],dstip)
                        flow = get_flow(switches,dstip)
                        flowDB[srcip][dstip]['icmp'] = {}
                        flowDB[srcip][dstip]['icmp']['default'] = [flow,'install']
                        flowDB[srcip][dstip][tcp_udp] = {}
                        flowDB[srcip][dstip][tcp_udp][port] = [flow,'install']

                    else:
                        print "srcip and dstip present icmp status not dropped overwriting old entries"
                        flow = get_flow(switches,dstip)
                        flowDB[srcip][dstip]['icmp'] = {}
                        flowDB[srcip][dstip]['icmp']['default'] = [flow,'install']
                        flowDB[srcip][dstip][tcp_udp] = {}
                        flowDB[srcip][dstip][tcp_udp][port] = [flow,'install']


                else:
                    print "srcip and dstip present icmp nor arp found"
                    flow = get_flow(switches,dstip)
                    flowDB[srcip][dstip]['icmp'] = {}
                    flowDB[srcip][dstip]['icmp']['default'] = [flow,'install']
                    flowDB[srcip][dstip][tcp_udp] = {}
                    flowDB[srcip][dstip][tcp_udp][port] = [flow,'install']

            else:
                print "srcip and dstip present tcpudp entry found looking for port numbers"
                if port in flowDB[srcip][dstip][tcp_udp] and flowDB[srcip][dstip][tcp_udp][port][1] == 'dropped':
                    print "srcip and dstip present tcpudp entry found port found and marked as dropped deleting the flows"
                    deletetcpudpflow(flowDB[srcip][dstip][tcp_udp][port][0],srcip,dstip,tcp_udp,port)
                    flow = get_flow(switches,dstip)
                    flowDB[srcip][dstip]['icmp'] = {}
                    flowDB[srcip][dstip]['arp'] = {}
                    flowDB[srcip][dstip]['icmp']['default'] = [flow,'install']
                    flowDB[srcip][dstip]['arp']['default'] = [flow,'install']
                    flowDB[srcip][dstip][tcp_udp] = {}
                    flowDB[srcip][dstip][tcp_udp][port] = [flow,'install']

                if port in flowDB[srcip][dstip][tcp_udp] and flowDB[srcip][dstip][tcp_udp][port][1] == 'install':
                    print "srcip and dstip present tcpudp entry found port found and marked as install overwriting the flows"
                    flow = get_flow(switches,dstip)
                    flowDB[srcip][dstip]['icmp'] = {}
                    flowDB[srcip][dstip]['arp'] = {}
                    flowDB[srcip][dstip]['icmp']['default'] = [flow,'install']
                    flowDB[srcip][dstip]['arp']['default'] = [flow,'install']
                    flowDB[srcip][dstip][tcp_udp] = {}
                    flowDB[srcip][dstip][tcp_udp][port] = [flow,'install']

    return 1
def sendFlowtoController(controller_ip,srcip,dstip,tcp_udp,portno,switches):
    global serversock

    build_link_stats(controller_ip)

    update_f = build_flowDB(srcip,dstip,portno,tcp_udp+'_dst',switches)
    switches.reverse()
    update_r = build_flowDB(dstip,srcip,portno,tcp_udp+'_src',switches)
    switches.reverse()
    
    if update_f and update_r:
        print "Updated the Flow DB "
        print "-------------------------------------------------------------"
        print flowDB
        print "-------------------------------------------------------------"
        try:
            serversock.send(str(flowDB)+'%'+str(arp_table))
            print "Sent the updated flow DB"
        except:
            print "Failed to send the flowDB"
    else:
        print "flow construction failed because of the improper list of switches"



def deletetcpudpsrcflow(controllerip,dpid,dstip,tcpudp,tcpport,out_port):

    if tcpudp == 'tcp':
        ip_proto = 6
    else:
        ip_proto = 17

    r = requests.post('http://'+controllerip+':8080/stats/flowentry/delete',data='{"dpid":"'+str('0x'+dpid[4:])+'","table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x0800,"nw_dst":"'+str(dstip)+'","ip_proto":'+ip_proto+',"'+tcpudp+'_src":"'+str(tcpport)+'"},"actions":[{"type":"OUTPUT","port": '+str(out_port)+'}]}')
    print "tcp flow mod for switch"
    print 'http://'+controllerip+':8080/stats/flowentry/delete,data={"dpid":"'+str('0x'+dpid[4:])+'","table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x0800,"nw_dst":"'+str(dstip)+'","ip_proto":'+ip_proto+','+tcpudp+'_src":"'+str(tcpport)+'"},"actions":[{"type":"OUTPUT","port": '+str(out_port)+'}]}'
    if r.status_code == requests.codes.ok:
        print "successfully removed tcp flow in the switch"
    else:
        print "failed removing flow "

def deletetcpudpdstflow(controllerip,dpid,dstip,tcpudp,tcpport,out_port):

    if tcpudp == 'tcp':
        ip_proto = 6
    else:
        ip_proto = 17

    r = requests.post('http://'+controllerip+':8080/stats/flowentry/delete',data='{"dpid":"'+str('0x'+dpid[4:])+'","table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x0800,"nw_dst":"'+str(dstip)+'","ip_proto":'+ip_proto+',"'+tcpudp+'_dst":"'+str(tcpport)+'"},"actions":[{"type":"OUTPUT","port": '+str(out_port)+'}]}')
    print "tcp flow mod for switch"
    print 'http://'+controllerip+':8080/stats/flowentry/delete,data={"dpid":"'+str('0x'+dpid[4:])+'","table_id": 0,"idle_timeout": 300,"hard_timeout": 300,"priority": 65535,"flags": 1,"match":{"eth_type":0x0800,"nw_dst":"'+str(dstip)+'","ip_proto":'+ip_proto+','+tcpudp+'_dst":"'+str(tcpport)+'"},"actions":[{"type":"OUTPUT","port": '+str(out_port)+'}]}'
    if r.status_code == requests.codes.ok:
        print "successfully removed tcp flow in the switch"
    else:
        print "failed removing flow "

def deleteflow(controllerip,srcip,dstip,switches,tcpudp,port):
    
    global flowDB
    global serversock

    if srcip in flowDB:
        if dstip in flowDB[srcip]:
            if tcpudp+'_dst' in flowDB[srcip][dstip]:
                for protocols in flowDB[srcip][dstip][tcpudp]:
                    print "sending delete flow request to the controller"
                    if protocols == port:
                        for switch in flowDB[srcip][dstip][tcpudp][protocols][0]:
                            deletetcpudpdstflow(controllerip, switch[0], dstip, tcpudp, port, switch[1])
                print "Emptying up the Flow DB for srcip %s dstip %s and sending to the controller" %(srcip,dstip)
                flowDB[srcip][dstip][tcpudp][port]=[]
                try:
                    serversock.send(str(flowDB))
                    print "Sent the updated flow DB"
                    return
                except:
                    print "Failed to send the flowDB"


    switches.reverse()
    if dstip in flowDB:
        if srcip in flowDB[dstip]:
            if tcpudp+'_src' in flowDB[dstip][srcip]:
                for protocols in flowDB[dstip][srcip][tcpudp]:
                    if protocols == port:
                        for switch in flowDB[dstip][srcip][tcpudp][protocols][0]:
                            deletetcpudpsrcflow(controllerip, switch[0], srcip, tcpudp, port, switch[1])

            
                print "Emptying up the Flow DB for dstip %s srcip %s and sending to the controller" %(dstip,srcip)
                flowDB[dstip][srcip][tcpudp][port]=[]
                try:
                    serversock.send(str(flowDB))
                    print "Sent the updated flow DB"
                    return
                except:
                    print "Failed to send the flowDB"
    switches.reverse()



def main():
    tcpconnect(controllerip)
    hostdiscoverythread = threading.Thread(target=hostDiscovery,args=())
    hostdiscoverythread.start()

    global serversock

    userinput = 'd'
    print "Enter (1) for insert flows, (2) for view flowDB, (3) delete flows, (4) view topology, (c) to exit"
    while (userinput != 'c'):
        if userinput == '1':
            srcip = raw_input("source ip address:")
            dstip = raw_input("destination ip address:")
            portno = raw_input("Port no:")
            protocol = raw_input("tcp/udp:")
            switches = raw_input("list of comma seperated switches").split(',')
            sendFlowtoController(controllerip,srcip,dstip,'tcp',portno,switches)
        elif userinput == '2':
            print "flow DataBase"
            print "--------------------------------------------------------------"
            print flowDB
            print "--------------------------------------------------------------"
        elif userinput == '3':
            srcip = raw_input("source ip address:")
            dstip = raw_input("destination ip address:")
            protocol = raw_input("tcp/udp:")
            portno = raw_input("Port no:")
            switches = raw_input("list of comma seperated switches").split(',')
            deleteflow(controllerip,srcip,dstip,switches,protocol,portno)
        elif userinput == '4':
            topologyviewer()
        elif userinput == '5':
            print "send random"
            serversock.send("random")
        print "Enter (1) for insert flows, (2) for view flowDB, (3) delete flows, (4) view topology, (c) to exit"
        userinput = raw_input()


    serversock.send('Kill thread')
    hostdiscoverythread._Thread__stop()

if __name__ == '__main__':
    main()



