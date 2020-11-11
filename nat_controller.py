import array
import ipaddress
import random

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ether, ofproto_v1_0, ofproto_v1_2, ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4, tcp, udp
from ryu.lib import mac, addrconv

import nat_config as config

class NatController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        '''Initialization of controller code'''
        super().__init__()

        self.arp_table = {}
        self.switch_table = {}
        self.pending_arp = {}
        self.ports_in_use = {}

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def handle_packet_in(self, event):
        '''Handles incoming OpenFlow packet'''

        of_packet = event.msg # openflow packet
        data_packet = packet.Packet(data=of_packet.data) # decapsulated packet


        print("############")
        print("arp table: ", self.arp_table)
        print("############\n")
        # Ignore IPv6 packets (not supported)
        if self.is_ipv6(data_packet):
            return
        #print("verify topoMap: ", config.hostIPToMACMap)
        self.debug('Handling packet: %s' % data_packet)
        self.debug('Reason: %s' % of_packet.reason)

        # Keep a record of MAC address incoming port
        self.switch_learn(of_packet, data_packet)
        print("switch table: ", self.switch_table)

        # Handle incoming ARP packet
        if self.is_arp(data_packet):
            self.debug("This is an arp packet")
            self.handle_incoming_arp(of_packet, data_packet)
        
        # Handle packet with destination MAC matching NAT external router MAC
        elif data_packet[0].dst == config.nat_external_mac:
            self.handle_incoming_external_msg(of_packet, data_packet)
        
        # Handle packet from inside the internal network
        else:
            self.handle_incoming_internal_msg(of_packet, data_packet)

    def switch_learn(self, of_packet, data_packet):
        '''Add entry in list of known MAC address to forward to specific links'''
        in_port = of_packet.match['in_port']
        src_mac = data_packet[0].src

        self.switch_table[src_mac] = in_port

    def switch_forward(self, of_packet, data_packet, actions=None):
        '''Forward to appropriate port (or flood) based on destination MAC address'''
        switch_id = of_packet.datapath.id
        dst_mac = data_packet[0].dst

        if dst_mac in self.switch_table:
            dst_port = self.switch_table[dst_mac]
        else:
            print("_-----------HEREEEEEEHELLLLLO--------------")
            dst_port = of_packet.datapath.ofproto.OFPP_FLOOD
        self.send_packet(of_packet.data, of_packet, dst_port, actions=actions)

    def router_next_hop(self, parser, src_mac, dst_mac):
        '''Returns a list of actions performed by a router when moving from one hop to the next'''
        
        return [parser.OFPActionDecNwTtl(), # Decrement network-layer TTL
                parser.OFPActionSetField(eth_src=src_mac),
                parser.OFPActionSetField(eth_dst=dst_mac)]
        
    def router_forward(self, of_packet, data_packet, next_ip,
                       match=None, extra_actions=None):
        '''
        Forward to appropriate port based on destination IP address. If
        match is set, also sends a flow update using the same actions
        for any future matching packet.
        '''
        #if next_ip not in config.hostIPToMACMap:
        if next_ip not in self.arp_table:
            self.send_arp_request(next_ip, of_packet, match, extra_actions)
            return
        dst_mac = self.arp_table[next_ip]
        #dst_mac = config.hostIPToMACMap[next_ip]
        src_mac = config.nat_external_mac if next_ip == config.nat_gateway_ip \
                  else config.nat_internal_mac
        
        parser = of_packet.datapath.ofproto_parser
        actions = self.router_next_hop(parser, src_mac, dst_mac)
        if extra_actions:
            actions += extra_actions

        self.switch_forward(of_packet, data_packet, actions)

        # This runs after switch_forward so that the output action is included.
        if match is not None:
            self.add_flow(of_packet.datapath, match, actions)
            
    def send_packet(self, payload, of_packet, port, actions=None):
        '''Send a packet to the switch for processing/forwarding'''
        
        switch = of_packet.datapath
        ofproto = switch.ofproto
        parser = switch.ofproto_parser

        if actions is None:
            actions = []
        if port is not None:
            actions.append(parser.OFPActionOutput(port))
        
        out = parser.OFPPacketOut(datapath=switch,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=of_packet.match['in_port'],
                                  actions=actions,
                                  data=payload)
        switch.send_msg(out)

    def add_flow(self, switch, match, actions):
        '''Send a new flow (match+action) to be added to a switch OpenFlow table'''

        self.debug('Adding a new flow:')
        self.debug(' - match: %s' % match)
        self.debug(' - actions: %s' % actions)
        ofproto = switch.ofproto
        parser = switch.ofproto_parser
        
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        modification = parser.OFPFlowMod(switch,
                                         match=match,
                                         instructions=instructions)
        switch.send_msg(modification)
        
    def handle_incoming_arp(self, of_packet, data_packet):
        '''Handles incoming ARP packet: update ARP table and send replies to suitable requests'''
        
        arp_src_ip = data_packet[1].src_ip
        arp_src_mac = data_packet[1].src_mac
        self.arp_table[arp_src_ip] = arp_src_mac
        print("arp table: ", self.arp_table);

        # For any packets waiting for this ARP reply to arrive, re-forward them
        if arp_src_ip in self.pending_arp:
            print("arp_src_ip", arp_src_ip, " is in self.pending_arp")
            for of_packet, match, actions in self.pending_arp[arp_src_ip]:
                self.router_forward(of_packet, packet.Packet(data=of_packet.data), arp_src_ip,
                                    match=match, extra_actions=actions)
            del self.pending_arp[arp_src_ip]
        
        if data_packet[1].opcode == 1:
            # ARP request
            #self.send_arp_reply(of_packet, data_packet)
            if self.send_arp_reply(of_packet, data_packet) == None:
                self.switch_forward(of_packet, data_packet)
        if data_packet[1].opcode == 2:
            print("--------OPCODE 2-------")
            self.switch_forward(of_packet, data_packet)

    def send_arp_request(self, ip, of_packet, match, actions):
        '''Send an ARP request for an IP with unknown MAC address'''

        self.debug('sending ARP request: IP %s' % ip)

        entry = (of_packet, match, actions)
        # If there is another pending ARP request, don't send it again.
        if ip in self.pending_arp:
            self.pending_arp[ip].append(entry)
            return
        # Save packet so it's sent back again once ARP reply returns
        self.pending_arp[ip] = [entry]
        
        if ip == config.nat_gateway_ip:
            src_mac = config.nat_external_mac
            src_ip = config.nat_external_ip
        else:
            src_mac = config.nat_internal_mac
            src_ip = config.nat_internal_ip
        
        eth_packet = ethernet.ethernet(dst='ff:ff:ff:ff:ff:ff', # Broadcast
                                       src=src_mac,
                                       ethertype=ether.ETH_TYPE_ARP)
        arp_packet = arp.arp(hwtype=1,
                             proto=ether.ETH_TYPE_IP,
                             hlen=6,
                             plen=4,
                             opcode=arp.ARP_REQUEST,
                             src_mac=src_mac,
                             src_ip=src_ip,
                             dst_mac='00:00:00:00:00:00',
                             dst_ip=ip)
        new_packet = packet.Packet()
        new_packet.add_protocol(eth_packet)
        new_packet.add_protocol(arp_packet)
        new_packet.serialize()
        self.send_packet(new_packet, of_packet, of_packet.datapath.ofproto.OFPP_FLOOD)
            
    def send_arp_reply(self, of_packet, data_packet):
        '''Builds and sends an ARP reply, if the IP corresponds to the switch'''
        
        arp_dst_ip = data_packet[1].dst_ip
        print("arp_dst_ip: ", arp_dst_ip)
        if arp_dst_ip == config.nat_internal_ip:
            arp_dst_mac = config.nat_internal_mac
        elif arp_dst_ip == config.nat_external_ip:
            arp_dst_mac = config.nat_external_mac
        # elif data_packet.get_protocol(ethernet.ethernet):
        #     pkt_eth = data_packet.get_protocol(ethernet.ethernet)
        #     arp_dst_mac = pkt_eth.dst
        else:
            return

        self.debug('Sending ARP reply: %s -> %s' % (arp_dst_ip, arp_dst_mac))

        eth_packet = ethernet.ethernet(dst=data_packet[1].src_mac,
                                       src=arp_dst_mac,
                                       ethertype=ether.ETH_TYPE_ARP)
        arp_packet = arp.arp(hwtype=1,
                             proto=ether.ETH_TYPE_IP,
                             hlen=6,
                             plen=4,
                             opcode=arp.ARP_REPLY,
                             src_mac=arp_dst_mac,
                             src_ip=arp_dst_ip,
                             dst_mac=data_packet[1].src_mac,
                             dst_ip=data_packet[1].src_ip)
        new_packet = packet.Packet()
        new_packet.add_protocol(eth_packet)
        new_packet.add_protocol(arp_packet)
        new_packet.serialize()
        self.send_packet(new_packet, of_packet, of_packet.datapath.ofproto.OFPP_IN_PORT)

    def is_arp(self, packet):
        return packet[0].ethertype == 2054

    def is_ipv4(self, packet):
        return packet[0].ethertype == 2048

    def is_icmp(self, packet):
        return packet[1].proto == 1

    def is_tcp(self, packet):
        return packet[1].proto == 6

    def is_udp(self, packet):
        return packet[1].proto == 17

    def is_ipv6(self, packet):
        return packet[0].ethertype == 34525

    def is_internal_network(self, ip):
        return ipaddress.ip_address(ip) in ipaddress.ip_network(config.nat_internal_net)

    def handle_incoming_external_msg(self, of_packet, data_packet):
        '''Handles a packet with destination MAC equal to external side of NAT router.'''
        
        # TODO Implement this function
        pass

    def handle_incoming_internal_msg(self, of_packet, data_packet):
        '''Handles a packet with destination MAC equal to internal side of NAT router.'''
        
        # checkForExtDstIp = [config.nat_internal_ip.split('.')[0], config.nat_internal_ip.split('.')[1]]
        # dst_ip = data_packet[1].dst  ## dest ip external host
        # if checkForExtDstIp[0]not in dst_ip or checkForExtDstIp[1] not in dst_ip:
        #     # print("sending ip packet to gateway router...")
        #     # parser = of_packet.datapath.ofproto_parser
        #     # actions = [parser.OFPActionSetField(ipv4_src = '4.4.2.1'), parser.OFPActionSetField(tcp_src = 2)]
        #     # self.send_packet(of_packet.data, of_packet, 1, actions)
        #     self.send_arp_request(config.nat_internal_ip, of_packet, None, None)

        # else :
        #     out_port = None
        #     dst_mac = data_packet[0].dst # router mac 
        #     if dst_mac in self.switch_table:
        #         out_port = self.switch_table[dst_mac]
        #         parser = of_packet.datapath.ofproto_parser
        #         match = parser.OFPMatch(in_port= of_packet.match['in_port'], eth_dst=dst_mac)
        #         actions = [parser.OFPActionOutput(out_port)]
        #         self.add_flow(of_packet.datapath, match, actions)
        #     self.switch_forward(of_packet, data_packet)
        
        dst_mac = data_packet[0].dst # mac addr of nat_internal
        in_port = of_packet.match['in_port']
        #out_port = self.switch_table[dst_mac] # port to send to (ie. the )
        out_port = None
        parser = of_packet.datapath.ofproto_parser
        next_ip = data_packet[1].dst # ipv4 dest 4.4.*.*
        ipv4_src = data_packet[1].src # ipv4 src 192.168.*.*
        tcp_src = data_packet[2].src_port # tcp src port usually rand #
        tcp_dst = data_packet[2].dst_port # tcp dst port usually 80

        match = parser.OFPMatch(in_port=in_port, 
                                eth_type=ether.ETH_TYPE_IP,
                                ipv4_src= ipv4_src,
                                ipv4_dst= next_ip,
                                tcp_src = tcp_src,
                                tcp_dst = tcp_dst
                                )
        actions = []
        actions.append(parser.OFPActionSetField(ipv4_src=config.nat_gateway_ip))
        self.router_forward(of_packet,data_packet, config.nat_gateway_ip, match, actions)
    def debug(self, str):
        print(str)