from time import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib import hub
from ryu.lib.packet import arp, lldp  # Import ARP and LLDP handling
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.lib.mac import haddr_to_bin
import requests
import threading


class MonitorTopology(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'switches': switches.Switches
    }


    def __init__(self, *args, **kwargs):
        super(MonitorTopology, self).__init__(*args, **kwargs)
        self.monitor_url = "http://analyze:5004/classify"
        self.datapaths = {}
        self.datapaths_lock = threading.Lock()
        self.mac_to_port = {}
        self.arp_table = {}
        self.switches = []
        self.links = []
        self.link_stats = {}  # Store link statistics
        self.link_timestamps = {}  # Track when links were last seen
        self.link_timeout = 30  # Link timeout in seconds
        self.topology_api_app = self
        self.topology_lock = threading.Lock()
        self.monitor_thread = hub.spawn(self._monitor)  # Monitor every 5 seconds
        self.discover_thread = hub.spawn(self._discover_topology)  # Discover topology
        self.cleanup_thread = hub.spawn(self._cleanup_old_links)  # Cleanup stale links
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
        # Match LLDP packets
        match = parser.OFPMatch(eth_type=0x88cc)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0xFFFF, match=match, actions=actions)
        
        # Enable LLDP packet output
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0xFFFF,
            match=match,
            instructions=inst,
            command=ofproto.OFPFC_ADD)
        datapath.send_msg(mod)

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

        # Handle LLDP packets
        if eth.ethertype == 0x88cc:
            # Process LLDP packet for topology discovery
            self._handle_lldp(datapath, msg.match['in_port'], pkt)
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

        # Handle IPv6 multicast packets (starting with 33:33)
        if dst.startswith('33:33'):
            # For IPv6 multicast, we only need to forward to edge ports
            # Avoid forwarding back to the input port
            out_ports = [port for port in self.mac_to_port[dpid].values() 
                        if port != in_port]
            if not out_ports:
                out_ports = [ofproto.OFPP_FLOOD]
            
            actions = [parser.OFPActionOutput(port) for port in out_ports]
            self.logger.info("IPv6 multicast forwarding to ports: {}".format(out_ports))
        else:
            # Regular unicast packet handling
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
                self.logger.info("Forwarding packet to port {}".format(out_port))
            else:
                out_port = ofproto.OFPP_FLOOD
                self.logger.info("Flooding unknown destination {}".format(dst))
            actions = [parser.OFPActionOutput(out_port)]

        # Install flows
        if dst.startswith('33:33'):
            # For IPv6 multicast, install a flow that forwards to all relevant ports
            match = parser.OFPMatch(in_port=in_port,
                                    eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)
        elif not dst.startswith('33:33') and out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(eth_src=src, eth_dst=dst)
            self.logger.info("Installing flow: switch={}, match=eth_src:{}, eth_dst:{}, out_port={}".format(dpid, src, dst, out_port))
            self.add_flow(datapath, priority=10, match=match, actions=actions)

        # Send the packet
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

        self.logger.info("Packet sent: switch={}, out_port={}".format(dpid, out_port))

    def _discover_topology(self):
        """Discover network topology using LLDP"""
        while True:
            try:
                # Get list of switches
                self.switches = get_switch(self.topology_api_app, None)
                self.links = get_link(self.topology_api_app, None)
                
                with self.topology_lock:
                    self.logger.info("Discovered {} switches".format(len(self.switches)))
                    for switch in self.switches:
                        self.logger.info("Switch: {}".format(switch.dp.id))
                        # Send LLDP packets out all ports
                        self._send_lldp_packets(switch.dp)
                    
                    active_links = [(link.src.dpid, link.src.port_no, link.dst.dpid, link.dst.port_no)
                                   for link in self.links]
                    
                    # Log active links and their statistics
                    self.logger.info("Active links: {}".format(len(active_links)))
                    for link_key in active_links:
                        if link_key in self.link_stats:
                            stats = self.link_stats[link_key]
                            self.logger.info("Link {} -> {}: {} packets, {} bytes".format(
                                link_key[0], link_key[2], stats['packets'], stats['bytes']))
                
            except Exception as e:
                self.logger.error("Error in topology discovery: {}".format(e))
            
            hub.sleep(5)  # Update topology every 5 seconds
            
    def _send_lldp_packets(self, datapath):
        """Send LLDP packets out of all ports on a switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Get all ports on the switch
        for port in datapath.ports.values():
            if port.port_no == ofproto.OFPP_LOCAL:
                continue
                
            # Create LLDP packet with switch and port info
            pkt = packet.Packet()
            
            # Create unique src MAC using switch ID and port
            src_mac = '00:00:00:%02x:%02x:%02x' % (datapath.id >> 16 & 0xFF,
                                                   datapath.id >> 8 & 0xFF,
                                                   datapath.id & 0xFF)
            
            pkt.add_protocol(ethernet.ethernet(
                ethertype=0x88cc,
                src=src_mac,
                dst='01:80:c2:00:00:0e'))
            
            # Format DPID as hex string
            dpid_str = 'dpid:{:016x}'.format(datapath.id)
            tlv_chassis_id = lldp.ChassisID(subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
                                           chassis_id=dpid_str.encode())
            tlv_port_id = lldp.PortID(subtype=lldp.PortID.SUB_PORT_COMPONENT,
                                     port_id=str(port.port_no).encode())
            tlv_ttl = lldp.TTL(ttl=120)
            tlv_end = lldp.End()
            
            tlvs = (tlv_chassis_id, tlv_port_id, tlv_ttl, tlv_end)
            pkt.add_protocol(lldp.lldp(tlvs))
            pkt.serialize()
            
            # Send packet out the specific port
            actions = [parser.OFPActionOutput(port.port_no)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=pkt.data)
            datapath.send_msg(out)
            
    def _handle_lldp(self, datapath, in_port, pkt):
        """Process incoming LLDP packet for topology discovery"""
        try:
            tlvs = pkt.protocols[-1].tlvs
            
            # Extract switch and port information from LLDP TLVs
            src_switch_id = None
            src_port_no = None
            
            for tlv in tlvs:
                if isinstance(tlv, lldp.ChassisID):
                    # Parse DPID from format 'dpid:0000000000000007'
                    chassis_id = tlv.chassis_id.decode('utf-8')
                    try:
                        if chassis_id.startswith('dpid:'):
                            src_switch_id = int(chassis_id[5:], 16)
                        else:
                            src_switch_id = int(chassis_id, 16)
                    except ValueError:
                        self.logger.error(f'Invalid DPID format: {chassis_id}')
                        return
                elif isinstance(tlv, lldp.PortID):
                    port_id = tlv.port_id.decode('utf-8')
                    try:
                        src_port_no = int(port_id)
                    except ValueError:
                        # Handle case where port_id might be in a different format
                        if ':' in port_id:
                            src_port_no = int(port_id.split(':')[1])
                    
            if src_switch_id is not None and src_port_no is not None:
                dst_switch_id = datapath.id
                dst_port_no = in_port
                
                # Update link information with timestamp
                link_key = (src_switch_id, src_port_no, dst_switch_id, dst_port_no)
                with self.topology_lock:
                    self.link_timestamps[link_key] = time()
                    
                    # Initialize or update link statistics
                    if link_key not in self.link_stats:
                        self.link_stats[link_key] = {
                            'packets': 0,
                            'bytes': 0,
                            'last_update': time()
                        }
                    
                    self.link_stats[link_key]['packets'] += 1
                    self.link_stats[link_key]['bytes'] += len(pkt.data)
                    self.link_stats[link_key]['last_update'] = time()
                    
                self.logger.info("LLDP link discovered: {} port {} -> {} port {}".format(
                    src_switch_id, src_port_no, dst_switch_id, dst_port_no))
        except Exception as e:
            self.logger.error("Error processing LLDP packet: {}".format(e))

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        """Handle switch enter events"""
        self.logger.info("Switch entered: {}".format(ev.switch.dp.id))
        self.switches = get_switch(self.topology_api_app, None)
        self.links = get_link(self.topology_api_app, None)

    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        """Handle switch leave events"""
        switch_id = ev.switch.dp.id
        self.logger.info("Switch left: {}".format(switch_id))
        
        # Clean up links associated with the departed switch
        with self.topology_lock:
            # Remove links where this switch was either source or destination
            stale_links = [link_key for link_key in self.link_timestamps
                          if link_key[0] == switch_id or link_key[2] == switch_id]
            
            for link_key in stale_links:
                if link_key in self.link_timestamps:
                    del self.link_timestamps[link_key]
                if link_key in self.link_stats:
                    del self.link_stats[link_key]
            
            if stale_links:
                self.logger.info("Removed {} stale links for switch {}".format(
                    len(stale_links), switch_id))
        
        # Update switch and link information
        self.switches = get_switch(self.topology_api_app, None)
        self.links = get_link(self.topology_api_app, None)

    def _cleanup_old_links(self):
        """Periodically clean up stale links that haven't been seen recently"""
        while True:
            try:
                current_time = time()
                with self.topology_lock:
                    # Find links that haven't been seen recently
                    stale_links = [link_key for link_key, timestamp in self.link_timestamps.items()
                                  if current_time - timestamp > self.link_timeout]
                    
                    # Remove stale links
                    for link_key in stale_links:
                        if link_key in self.link_timestamps:
                            del self.link_timestamps[link_key]
                        if link_key in self.link_stats:
                            del self.link_stats[link_key]
                    
                    if stale_links:
                        self.logger.info("Cleaned up {} stale links".format(len(stale_links)))
            
            except Exception as e:
                self.logger.error("Error in link cleanup: {}".format(e))
            
            hub.sleep(10)  # Run cleanup every 10 seconds
