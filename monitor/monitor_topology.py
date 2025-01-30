import os
import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ether_types
from ryu.lib import hub
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController
from mininet.log import setLogLevel, info
from mininet.cli import CLI
import threading
import requests
import subprocess



class CustomTopo(Topo):
    """
    Create a tree topology with a specified depth and fanout.
    """
    def build(self, depth=2, fanout=2):
        self._add_tree(depth, fanout)

    def _add_tree(self, depth, fanout, parent=None):
        if depth == 0:
            return
        switch = self.addSwitch('s{}'.format(len(self.switches()) + 1))
        if parent:
            self.addLink(parent, switch)

        for _ in range(fanout):
            if depth == 1:
                host = self.addHost('h{}'.format(len(self.hosts()) + 1))
                self.addLink(switch, host)
            else:
                self._add_tree(depth - 1, fanout, switch)

class MonitorTopology(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MonitorTopology, self).__init__(*args, **kwargs)
        self.monitor_url = "http://analyze:5004/classify"
        self.datapaths = {}
        self.datapaths_lock = threading.Lock()
        self.mac_to_port = {}  # {dpid: {mac: port}}
        self.arp_table = {}  # {IP: MAC}
        self.monitor_thread = hub.spawn(self._monitor)
        self.flow_timestamps = {}

        # Start Mininet topology
        self._start_mininet_topology()
        self.dos_thread = hub.spawn(self._simulate_dos_attack)

        self.logger.info("MonitorTopology app initialized.")


    def compute_iat(self, flow_id, current_timestamp):
        if flow_id not in self.flow_timestamps:
            self.flow_timestamps[flow_id] = []

        timestamps = self.flow_timestamps[flow_id]
        if timestamps:
            # Calculate IAT metrics
            iats = [current_timestamp - ts for ts in timestamps]
            iat_mean = sum(iats) / len(iats)
            iat_std = (sum([(x - iat_mean) ** 2 for x in iats]) / len(iats)) ** 0.5
            iat_max = max(iats)
            iat_min = min(iats)
        else:
            iat_mean, iat_std, iat_max, iat_min = 0, 0, 0, 0

        # Update timestamps
        self.flow_timestamps[flow_id].append(current_timestamp)
        return iat_mean, iat_std, iat_max, iat_min


    def _start_mininet_topology(self):
        """
        Start Mininet topology programmatically.
        """
        setLogLevel('info')

        self.logger.info("Starting Mininet topology...")
        topo = CustomTopo(depth=3, fanout=2)
        self.net = Mininet(topo=topo, controller=None)
        self.net.addController('ryu', controller=RemoteController, ip='127.0.0.1', port=6653)
        self.net.start()
        self.logger.info("Mininet topology started.")

        # Optionally launch the Mininet CLI
        # hub.spawn(self._start_cli)

    def _start_cli(self):
        """
        Launch the Mininet CLI in a separate thread.
        """
        self.logger.info("Launching Mininet CLI...")
        CLI(self.net)
        self.logger.info("Mininet CLI terminated.")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        with self.datapaths_lock:
            self.datapaths[datapath.id] = datapath

        self.logger.info("Switch connected: datapath_id=%s", datapath.id)

        # Install default flow rules
        self.add_lldp_flow(datapath)  # For link discovery
        self.add_arp_flow(datapath)  # For host discovery
        self.add_default_flow(datapath)  # Catch-all flow to forward unmatched packets to the controller
        self.add_broadcast_flow(datapath)

    def add_default_flow(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)
        self.logger.info("Default flow added for datapath_id=%s", datapath.id)

    def add_lldp_flow(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(eth_type=0x88cc)  # Match LLDP packets
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=10, match=match, actions=actions)
        self.logger.info("LLDP flow added for datapath_id=%s", datapath.id)

    def add_arp_flow(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=10, match=match, actions=actions)
        self.logger.info("ARP flow added for datapath_id=%s", datapath.id)


    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # Set the flow modification message
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=instructions,
                buffer_id=buffer_id,
                table_id=0,
                command=ofproto.OFPFC_ADD,
                out_group=ofproto.OFPG_ANY,  # Explicitly setting out_group
                out_port=ofproto.OFPP_ANY,  # Explicitly setting out_port
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=instructions,
                table_id=0,
                command=ofproto.OFPFC_ADD,
                out_group=ofproto.OFPG_ANY,  # Explicitly setting out_group
                out_port=ofproto.OFPP_ANY,  # Explicitly setting out_port
            )

        datapath.send_msg(mod)
        self.logger.info("Flow added: datapath=%s, priority=%s, match=%s", datapath.id, priority, match)


    def _monitor(self):
        while True:
            with self.datapaths_lock:
                for dp in self.datapaths.values():
                    self._request_stats(dp)
            hub.sleep(30)
    
    def _simulate_dos_attack(self):
        """
        Simulates a DoS attack at specific intervals.
        - h3 is set up as an HTTP server
        - h1, h2, and h4 flood h3 using hping3
        """
        self.logger.info("Starting DoS attack simulation thread...")

        # Workaround for subprocess.DEVNULL in older Python versions
        try:
            DEVNULL = subprocess.DEVNULL  #Python 3.3+
        except AttributeError:
            DEVNULL = open(os.devnull, 'wb')  # Fallback for older versions

        while True:
            try:
                # **Start HTTP server on h3**
                self.logger.info("Starting HTTP server on h3...")
                h3 = self.net.get('h3')  # Ensure h3 exists
                h3.cmd("python3 -m http.server 80 &")  # Start HTTP server in the background

                # **Wait a few seconds before attack starts**
                time.sleep(5)

                # **Start DoS attack from h1, h2, h4**
                self.logger.info("Launching DoS attack from h1, h2, h4...")

                attack_cmds = [
                    "h1 hping3 --flood --syn -p 80 10.0.0.3 &",
                    "h2 hping3 --flood --syn -p 80 10.0.0.3 &",
                ]

                for cmd in attack_cmds:
                    self.net.get(cmd.split()[0]).cmd(cmd)  # Execute in Mininet hosts

                # **Attack duration (10 seconds)**
                time.sleep(10)

                # **Stop the attack**
                self.logger.info("Stopping DoS attack...")
                for host in ['h1', 'h2', 'h4']:
                    self.net.get(host).cmd("pkill -f hping3")

                # **Wait before next attack (e.g., 30 seconds)**
                time.sleep(30)

            except Exception as e:
                self.logger.error("Error in DoS attack simulation: {}".format(e))

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        try:
            datapath.send_msg(req)
            self.logger.info("Stats requested for datapath_id=%s", datapath.id)
        except Exception as e:
            self.logger.error("Failed to request stats from datapath %s: %s", datapath.id, e)
    

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        datapath_id = ev.msg.datapath.id
        self.logger.info("Flow stats received for datapath_id=%s", datapath_id)
        flow_stats = []

        for stat in ev.msg.body:
            flow_id = (datapath_id, stat.match)

            # Retrieve packet stats for the flow
            packet_lengths = self.mac_to_port.get(flow_id, {}).get("packet_lengths", [])
            iat_values = self.mac_to_port.get(flow_id, {}).get("iat_values", [])

            # Compute metrics
            packet_length_mean = sum(packet_lengths) / len(packet_lengths) if packet_lengths else 0
            packet_length_std = (sum([(x - packet_length_mean) ** 2 for x in packet_lengths]) / len(packet_lengths)) ** 0.5 if packet_lengths else 0
            iat_mean = sum(iat_values) / len(iat_values) if iat_values else 0
            iat_std = (sum([(x - iat_mean) ** 2 for x in iat_values]) / len(iat_values)) ** 0.5 if iat_values else 0
            iat_max = max(iat_values) if iat_values else 0
            iat_min = min(iat_values) if iat_values else 0

            # Append stats
            flow_stats.append({
                "datapath_id": datapath_id,
                "flow_duration": stat.duration_sec + stat.duration_nsec / 1e9,
                "packet_count": stat.packet_count,
                "byte_count": stat.byte_count,
                "packet_rate": stat.packet_count / max(stat.duration_sec + stat.duration_nsec / 1e9, 1e-6),
                "byte_rate": stat.byte_count / max(stat.duration_sec + stat.duration_nsec / 1e9, 1e-6),
        })

        if flow_stats:
            try:
                response = requests.post("{}".format(self.monitor_url), json={"flows": flow_stats})
                response.raise_for_status()
                self.logger.info("Flow stats successfully sent to Analyzer.")
            except requests.exceptions.RequestException as e:
                self.logger.error("Failed to send flow stats to Analyzer:")

           

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            self.logger.info("LLDP packet received: datapath_id=%s, in_port=%s", datapath.id, in_port)
            return

        # Handle ARP packets
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.logger.info("ARP received: src_ip=%s, src_mac=%s, dst_ip=%s",
                             arp_pkt.src_ip, eth.src, arp_pkt.dst_ip)

            # Learn the source IP and MAC address
            self.arp_table[arp_pkt.src_ip] = eth.src

            # Reply to ARP requests
            if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip in self.arp_table:
                self.logger.info("Replying to ARP request for %s", arp_pkt.dst_ip)
                self._send_arp_reply(datapath, arp_pkt, in_port)
                return

        # Flood unknown packets
        out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                              in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        self.logger.info("Flooding packet from port %s on datapath %s", in_port, datapath.id)



    def _send_arp_reply(self, datapath, arp_request, in_port):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        src_mac = self.arp_table[arp_request.dst_ip]
        dst_mac = arp_request.src_mac
        src_ip = arp_request.dst_ip
        dst_ip = arp_request.src_ip

        # Create ARP reply packet
        arp_reply = packet.Packet()
        arp_reply.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=dst_mac,
            src=src_mac
        ))
        arp_reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac=dst_mac,
            dst_ip=dst_ip
        ))
        arp_reply.serialize()

        # Send ARP reply
        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                              in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=arp_reply.data)
        datapath.send_msg(out)
        self.logger.info("Sent ARP reply to %s for %s", dst_ip, src_ip)

    def add_broadcast_flow(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(eth_dst="ff:ff:ff:ff:ff:ff")  # Match broadcast MAC address
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]  # Flood the broadcast packet
        self.add_flow(datapath, priority=20, match=match, actions=actions)



 