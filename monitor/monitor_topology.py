from time import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib import hub
from ryu.lib.packet import arp  # Import ARP handling
import requests
import threading


class MonitorTopology(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


    def __init__(self, *args, **kwargs):
        super(MonitorTopology, self).__init__(*args, **kwargs)
        self.monitor_url = "http://analyze:5004/classify"
        self.datapaths = {}
        self.datapaths_lock = threading.Lock()
        self.mac_to_port = {}
        self.arp_table = {}
        self.monitor_thread = hub.spawn(self._monitor)  # Monitor every 5 seconds
        self.logger.info("MonitorTopology Controller Initialized with REST API")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        with self.datapaths_lock:
            self.datapaths[datapath.id] = datapath
        self.logger.info("Switch connected: datapath_id=%s", datapath.id)
        self.add_default_flow(datapath)
        self.add_lldp_flow(datapath)
        self.add_arp_flow(datapath)
        self.add_broadcast_flow(datapath)

    def add_default_flow(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)

    def add_lldp_flow(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(eth_type=0x88cc)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=10, match=match, actions=actions)

    def add_arp_flow(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=10, match=match, actions=actions)

    def add_broadcast_flow(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(eth_dst="ff:ff:ff:ff:ff:ff")
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, priority=20, match=match, actions=actions)


    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            idle_timeout=idle_timeout, hard_timeout=hard_timeout,
            instructions=instructions
        )
        datapath.send_msg(mod)
        self.logger.info("Flow added: {}, priority={}, idle_timeout={}, hard_timeout={}".format(match, priority, idle_timeout, hard_timeout))


    def _monitor(self):
        while True:
            with self.datapaths_lock:
                for dp in self.datapaths.values():
                    self.logger.info("Requesting flow stats from switch {}".format(dp.id))
                    self._request_stats(dp)
                    # Re-register the switch if missing
                    if dp.id not in self.datapaths:
                        self.datapaths[dp.id] = dp
                        self.logger.info("Re-registering switch {} in self.datapaths".format(dp.id))
            hub.sleep(5)


    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        self.logger.info("Requesting flow stats from switch {}".format(datapath.id))
        datapath.send_msg(req)

        # Ensure switch is always tracked
        if datapath.id not in self.datapaths:
            self.datapaths[datapath.id] = datapath
            self.logger.info("Re-added switch {} to self.datapaths".format(datapath.id))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """ Logs flow statistics, stores them, and sends them to an external analyzer. """
        datapath_id = ev.msg.datapath.id

        self.logger.info("Flow stats received from switch {}".format(datapath_id))

        # Ensure self.flow_stats exists
        if not hasattr(self, 'flow_stats'):
            self.flow_stats = {}

        # If the switch is not in self.flow_stats, initialize it
        if datapath_id not in self.flow_stats:
            self.flow_stats[datapath_id] = []

        flow_stats = []  # Temporary list to send to the analyzer

        for stat in ev.msg.body:
            packet_rate = stat.packet_count / max(stat.duration_sec + stat.duration_nsec / 1e9, 1e-6)
            byte_rate = stat.byte_count / max(stat.duration_sec + stat.duration_nsec / 1e9, 1e-6)

            flow_data = {
                "datapath_id": datapath_id,
                "flow_duration": stat.duration_sec + stat.duration_nsec / 1e9,
                "packet_count": stat.packet_count,
                "byte_count": stat.byte_count,
                "packet_rate": packet_rate,
                "byte_rate": byte_rate
            }

            self.logger.info("Switch {} - Flow: {}".format(datapath_id, flow_data))

            # Store the flow in self.flow_stats
            self.flow_stats[datapath_id].append(flow_data)

            # Also prepare stats for the external analyzer
            flow_stats.append(flow_data)

        self.logger.info("Stored {} flows for switch {}".format(len(self.flow_stats[datapath_id]), datapath_id))

        # Send flow stats to the external analyzer
        if flow_stats:
            try:
                response = requests.post(self.monitor_url, json={"flows": flow_stats})
                response.raise_for_status()
                self.logger.info("Flow stats sent to Analyzer: {}".format(self.monitor_url))
            except requests.exceptions.RequestException as e:
                self.logger.error("Failed to send flow stats to Analyzer: {}".format(e))
    


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            self.logger.warning("Received non-Ethernet packet")
            return

        src = eth.src
        dst = eth.dst
        dpid = datapath.id
        in_port = msg.match['in_port']

        self.logger.info("Packet-In: switch={}, in_port={}, src={}, dst={}".format(dpid, in_port, src, dst))

        self.mac_to_port.setdefault(dpid, {})

        # Learn source MAC address
        self.mac_to_port[dpid][src] = in_port

        # Handle ARP packets explicitly
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            if arp_pkt.opcode == arp.ARP_REQUEST:
                self.logger.info("ARP Request from {} for {}".format(src, arp_pkt.dst_ip))
            elif arp_pkt.opcode == arp.ARP_REPLY:
                self.logger.info("ARP Reply from {} to {}".format(src, arp_pkt.dst_ip))

            # Forward ARP replies correctly
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
                self.logger.info("Forwarding ARP Reply to port {}".format(out_port))
            else:
                out_port = ofproto.OFPP_FLOOD
                self.logger.info("Flooding ARP Packet")

            actions = [parser.OFPActionOutput(out_port)]
            data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None

            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

            return  # Stop processing here if it's an ARP packet

        # If we know the destination, forward it
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            self.logger.info("Forwarding packet to port {}".format(out_port))
        else:
            out_port = ofproto.OFPP_FLOOD
            self.logger.info("Flooding unknown destination {}".format(dst))

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow for known destinations
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(eth_src=src, eth_dst=dst)
            self.logger.info("Installing flow: switch={}, match=eth_src:{}, eth_dst:{}, out_port={}".format(dpid, src, dst, out_port))
            self.add_flow(datapath, priority=10, match=match, actions=actions)

        # Send the packet
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

        self.logger.info("Packet sent: switch={}, out_port={}".format(dpid, out_port))
