from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import queue
import time
import random
from datetime import datetime
from rqa import RQAAnalyzer

class PacketSniffer:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.is_running = False
        self.sniffer_thread = None
        self.rqa = RQAAnalyzer(window_size=50, epsilon=100) # Window 50, Epsilon 100 bytes
        
    def start(self):
        """Starts the packet sniffer in a background thread."""
        if self.is_running:
            return
            
        self.is_running = True
        self.sniffer_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.sniffer_thread.start()
        print("🕵️ Packet Sniffer started...")

    def stop(self):
        """Stops the packet sniffer."""
        self.is_running = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=1)
            
    def _sniff_packets(self):
        """Internal method to capture packets."""
        # Filter for IP traffic only to avoid clutter
        try:
            sniff(filter="ip", prn=self._process_packet, store=0, stop_filter=lambda x: not self.is_running)
        except Exception as e:
            print(f"⚠️ Sniffer Error (Check Npcap/Permissions): {e}")
            self.is_running = False

    def _process_packet(self, packet):
        """Callback to process each captured packet."""
        if not self.is_running:
            return

        if IP in packet:
            try:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                length = len(packet)
                
                # Update RQA with packet length
                self.rqa.add_data_point(length)
                rqa_metrics = self.rqa.calculate_rqa()
                
                protocol = 'other'
                service = 'other'
                flag = 'SF' # Default flag
                
                if TCP in packet:
                    protocol = 'tcp'
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        service = 'http'
                    elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                        service = 'http_ssl'
                    elif packet[TCP].dport == 22:
                        service = 'ssh'
                    elif packet[TCP].dport == 21:
                        service = 'ftp'
                    elif packet[TCP].dport == 25:
                        service = 'smtp'
                    else:
                        service = 'private'
                        
                    # Simple flag mapping (approximation)
                    flags = packet[TCP].flags
                    if 'S' in flags and 'F' not in flags: flag = 'S0'
                    elif 'R' in flags: flag = 'REJ'
                    
                elif UDP in packet:
                    protocol = 'udp'
                    if packet[UDP].dport == 53:
                        service = 'domain_u'
                    else:
                        service = 'private'
                        
                elif ICMP in packet:
                    protocol = 'icmp'
                    service = 'ecr_i'

                # Construct traffic object compatible with our model
                traffic_data = {
                    'duration': random.randint(0, 50), # Real duration is hard to track per packet
                    'protocol_type': protocol,
                    'service': service,
                    'flag': flag,
                    'src_bytes': length,
                    'dst_bytes': random.randint(0, length), # Approx
                    'land': 1 if src_ip == dst_ip else 0,
                    'wrong_fragment': 0,
                    'urgent': 0,
                    'hot': 0,
                    'num_failed_logins': 0,
                    'logged_in': 1 if service in ['http', 'ssh'] else 0,
                    'num_compromised': 0,
                    'root_shell': 0,
                    'su_attempted': 0,
                    'num_root': 0,
                    'num_file_creations': 0,
                    'num_shells': 0,
                    'num_access_files': 0,
                    'num_outbound_cmds': 0,
                    'is_host_login': 0,
                    'is_guest_login': 0,
                    'count': random.randint(1, 10),
                    'srv_count': random.randint(1, 10),
                    'serror_rate': 0.0,
                    'srv_serror_rate': 0.0,
                    'rerror_rate': 0.0,
                    'srv_rerror_rate': 0.0,
                    'same_srv_rate': 1.0,
                    'diff_srv_rate': 0.0,
                    'srv_diff_host_rate': 0.0,
                    'dst_host_count': random.randint(1, 255),
                    'dst_host_srv_count': random.randint(1, 255),
                    'dst_host_same_srv_rate': 1.0,
                    'dst_host_diff_srv_rate': 0.0,
                    'dst_host_same_src_port_rate': 0.0,
                    'dst_host_srv_diff_host_rate': 0.0,
                    'dst_host_serror_rate': 0.0,
                    'dst_host_srv_serror_rate': 0.0,
                    'dst_host_rerror_rate': 0.0,
                    'dst_host_srv_rerror_rate': 0.0,
                    
                    # Metadata for display
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'timestamp': datetime.now().isoformat(),
                    
                    # RQA Metrics
                    'rqa_rr': rqa_metrics['rr'],
                    'rqa_det': rqa_metrics['det']
                }
                
                self.packet_queue.put(traffic_data)
                
            except Exception as e:
                # print(f"Error processing packet: {e}")
                pass

    def get_packet(self):
        """Retrieves a packet from the queue if available."""
        try:
            return self.packet_queue.get_nowait()
        except queue.Empty:
            return None
