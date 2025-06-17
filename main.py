#!/usr/bin/env python3
"""

Requirements:
- pip install scapy psutil
- For full functionality, run as administrator on Windows
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import os
import sys
import subprocess
from datetime import datetime
import socket
import struct

try:
    from scapy.all import *
    from scapy.interfaces import get_working_ifaces
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

class NetworkMonitor:
    """Alternative network monitoring using socket when scapy fails"""
    
    def __init__(self):
        self.packets = []
        self.capturing = False
        self.sock = None
        
    def create_raw_socket(self):
        """Create raw socket for packet capture"""
        try:
            if os.name == 'nt':  # Windows
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.sock.bind(('0.0.0.0', 0))
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                # Enable promiscuous mode on Windows
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:  # Linux/Unix
                self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            return True
        except Exception as e:
            print(f"Raw socket creation failed: {e}")
            return False
            
    def parse_ip_packet(self, packet_data):
        """Parse IP packet manually"""
        try:
            # IP header is first 20 bytes
            ip_header = struct.unpack('!BBHHHBBH4s4s', packet_data[:20])
            
            version_ihl = ip_header[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            
            ttl = ip_header[5]
            protocol = ip_header[6]
            src_addr = socket.inet_ntoa(ip_header[8])
            dst_addr = socket.inet_ntoa(ip_header[9])
            
            protocol_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(protocol, f'Protocol {protocol}')
            
            return {
                'src': src_addr,
                'dst': dst_addr,
                'protocol': protocol_name,
                'length': len(packet_data),
                'ttl': ttl
            }
        except:
            return None
            
    def start_capture_socket(self, callback):
        """Start capture using raw socket"""
        if not self.create_raw_socket():
            return False
            
        self.capturing = True
        
        try:
            while self.capturing:
                try:
                    packet_data, addr = self.sock.recvfrom(65535)
                    packet_info = self.parse_ip_packet(packet_data)
                    
                    if packet_info:
                        packet_info['timestamp'] = datetime.now().strftime('%H:%M:%S.%f')[:-3]
                        packet_info['info'] = f"IP packet from {packet_info['src']} to {packet_info['dst']}"
                        packet_info['raw_packet'] = packet_data
                        callback(packet_info)
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.capturing:
                        print(f"Capture error: {e}")
                    break
                    
        finally:
            if self.sock:
                if os.name == 'nt':
                    self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                self.sock.close()
                
        return True

class PacketAnalyzer:
    def __init__(self):
        self.packets = []
        self.capturing = False
        self.capture_thread = None
        self.monitor = NetworkMonitor()
        
    def analyze_packet(self, packet):
        """Analyze a packet and extract relevant information"""
        info = {
            'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'src': 'Unknown',
            'dst': 'Unknown',
            'protocol': 'Unknown',
            'length': len(packet) if hasattr(packet, '__len__') else 0,
            'info': '',
            'raw_packet': packet
        }
        
        # If it's already parsed (from socket capture)
        if isinstance(packet, dict):
            return packet
            
        if not SCAPY_AVAILABLE:
            return info
            
        try:
            # Ethernet layer
            if packet.haslayer(Ether):
                eth = packet[Ether]
                info['src'] = eth.src
                info['dst'] = eth.dst
                
            # IP layer
            if packet.haslayer(IP):
                ip = packet[IP]
                info['src'] = ip.src
                info['dst'] = ip.dst
                info['protocol'] = ip.proto
                
                # TCP layer
                if packet.haslayer(TCP):
                    tcp = packet[TCP]
                    info['protocol'] = 'TCP'
                    info['info'] = f"Port {tcp.sport} → {tcp.dport}"
                    
                    # HTTP detection
                    if tcp.dport == 80 or tcp.sport == 80:
                        info['protocol'] = 'HTTP'
                    elif tcp.dport == 443 or tcp.sport == 443:
                        info['protocol'] = 'HTTPS'
                        
                # UDP layer
                elif packet.haslayer(UDP):
                    udp = packet[UDP]
                    info['protocol'] = 'UDP'
                    info['info'] = f"Port {udp.sport} → {udp.dport}"
                    
                    # DNS detection
                    if udp.dport == 53 or udp.sport == 53:
                        info['protocol'] = 'DNS'
                        if packet.haslayer(DNS):
                            dns = packet[DNS]
                            if dns.qr == 0:  # Query
                                info['info'] = f"DNS Query: {dns.qd.qname.decode()}"
                            else:  # Response
                                info['info'] = f"DNS Response"
                                
                # ICMP layer
                elif packet.haslayer(ICMP):
                    icmp = packet[ICMP]
                    info['protocol'] = 'ICMP'
                    info['info'] = f"Type {icmp.type} Code {icmp.code}"
                    
            # ARP layer
            elif packet.haslayer(ARP):
                arp = packet[ARP]
                info['protocol'] = 'ARP'
                info['src'] = arp.psrc
                info['dst'] = arp.pdst
                if arp.op == 1:
                    info['info'] = f"Who has {arp.pdst}? Tell {arp.psrc}"
                elif arp.op == 2:
                    info['info'] = f"{arp.psrc} is at {arp.hwsrc}"
                    
        except Exception as e:
            info['info'] = f"Parse error: {str(e)}"
            
        return info

class NetworkAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Analyzer - Enhanced Version")
        self.root.geometry("1200x800")
        
        self.analyzer = PacketAnalyzer()
        self.selected_packet = None
        self.capture_method = "scapy"  # or "socket"
        
        self.setup_gui()
        self.check_capabilities()
        self.update_packet_list()
        
    def check_capabilities(self):
        """Check what capture methods are available"""
        capabilities = []
        
        if SCAPY_AVAILABLE:
            capabilities.append("Scapy available")
            try:
                # Test if we can create a raw socket
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                test_sock.close()
                capabilities.append("Raw socket access")
            except:
                capabilities.append("Raw socket access denied - need admin privileges")
        else:
            capabilities.append("Scapy not installed")
            
        # Check if running as admin (Windows)
        if os.name == 'nt':
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if is_admin:
                    capabilities.append("Running as Administrator")
                else:
                    capabilities.append("Not running as Administrator")
            except:
                capabilities.append("Cannot determine admin status")
                
        self.status_var.set(" | ".join(capabilities))
        
    def setup_gui(self):
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Control frame
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 5))
        
        # Interface selection
        ttk.Label(control_frame, text="Interface:").pack(side=tk.LEFT, padx=(0, 5))
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(control_frame, textvariable=self.interface_var, width=20)
        self.interface_combo.pack(side=tk.LEFT, padx=(0, 10))
        
        # Populate interfaces
        self.populate_interfaces()
        
        # Capture method selection
        ttk.Label(control_frame, text="Method:").pack(side=tk.LEFT, padx=(10, 5))
        self.method_var = tk.StringVar(value="auto")
        method_combo = ttk.Combobox(control_frame, textvariable=self.method_var, 
                                   values=["auto", "scapy", "socket"], width=10)
        method_combo.pack(side=tk.LEFT, padx=(0, 10))
        
        # Control buttons
        self.start_btn = ttk.Button(control_frame, text="Start Capture", command=self.start_capture)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.stop_btn = ttk.Button(control_frame, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.clear_btn = ttk.Button(control_frame, text="Clear", command=self.clear_packets)
        self.clear_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        # Generate test packets button
        self.test_btn = ttk.Button(control_frame, text="Generate Test Packets", command=self.generate_test_packets)
        self.test_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        # Filter frame
        filter_frame = ttk.Frame(main_frame)
        filter_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=(0, 5))
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=50)
        self.filter_entry.pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(filter_frame, text="Apply", command=self.apply_filter).pack(side=tk.LEFT)
        
        # Status bar
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.status_var = tk.StringVar()
        self.status_var.set("Initializing...")
        status_label = ttk.Label(status_frame, textvariable=self.status_var)
        status_label.pack(side=tk.LEFT)
        
        self.packet_count_var = tk.StringVar()
        self.packet_count_var.set("Packets: 0")
        ttk.Label(status_frame, textvariable=self.packet_count_var).pack(side=tk.RIGHT)
        
        # Packet list frame
        packet_frame = ttk.Frame(main_frame)
        packet_frame.pack(fill=tk.BOTH, expand=True)
        
        # Packet list (top half)
        list_frame = ttk.Frame(packet_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview for packet list
        columns = ('Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info')
        self.packet_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=120)
            
        self.packet_tree.bind('<<TreeviewSelect>>', self.on_packet_select)
        
        # Scrollbar for packet list
        packet_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=packet_scrollbar.set)
        
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        packet_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Packet details frame (bottom half)
        details_frame = ttk.Frame(main_frame)
        details_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
        # Notebook for different views
        self.notebook = ttk.Notebook(details_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Packet details tab
        details_tab = ttk.Frame(self.notebook)
        self.notebook.add(details_tab, text="Packet Details")
        
        self.details_text = scrolledtext.ScrolledText(details_tab, height=10, font=('Courier', 10))
        self.details_text.pack(fill=tk.BOTH, expand=True)
        
        # Hex dump tab
        hex_tab = ttk.Frame(self.notebook)
        self.notebook.add(hex_tab, text="Hex Dump")
        
        self.hex_text = scrolledtext.ScrolledText(hex_tab, height=10, font=('Courier', 10))
        self.hex_text.pack(fill=tk.BOTH, expand=True)
        
    def populate_interfaces(self):
        """Populate network interfaces"""
        interfaces = []
        
        if SCAPY_AVAILABLE:
            try:
                ifaces = get_working_ifaces()
                interfaces.extend([iface.name for iface in ifaces])
            except:
                pass
                
        if PSUTIL_AVAILABLE:
            try:
                net_if = psutil.net_if_addrs()
                interfaces.extend(list(net_if.keys()))
            except:
                pass
                
        # Fallback interfaces
        if not interfaces:
            if os.name == 'nt':  # Windows
                interfaces = ['Ethernet', 'Wi-Fi', 'Local Area Connection']
            else:  # Linux/Unix
                interfaces = ['eth0', 'wlan0', 'lo']
                
        # Remove duplicates
        interfaces = list(set(interfaces))
        
        self.interface_combo['values'] = interfaces
        if interfaces:
            self.interface_combo.set(interfaces[0])
            
    def generate_test_packets(self):
        """Generate test packets for demonstration"""
        test_packets = [
            {
                'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'src': '192.168.1.100',
                'dst': '8.8.8.8',
                'protocol': 'TCP',
                'length': 1024,
                'info': 'Test HTTP Request to Google DNS',
                'raw_packet': b'Test packet data for HTTP request'
            },
            {
                'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'src': '192.168.1.1',
                'dst': '192.168.1.255',
                'protocol': 'ARP',
                'length': 42,
                'info': 'Who has 192.168.1.100? Tell 192.168.1.1',
                'raw_packet': b'Test ARP packet data'
            },
            {
                'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'src': '192.168.1.100',
                'dst': '8.8.8.8',
                'protocol': 'DNS',
                'length': 64,
                'info': 'DNS Query: example.com',
                'raw_packet': b'Test DNS query packet'
            }
        ]
        
        for packet in test_packets:
            self.analyzer.packets.append(packet)
            self.add_packet_to_tree(packet)
        
    def start_capture(self):
        """Start packet capture"""
        interface = self.interface_var.get()
        method = self.method_var.get()
        
        if not interface:
            messagebox.showerror("Error", "Please select a network interface")
            return
            
        self.analyzer.capturing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        # Determine capture method
        if method == "auto":
            if SCAPY_AVAILABLE:
                capture_method = "scapy"
            else:
                capture_method = "socket"
        else:
            capture_method = method
            
        self.status_var.set(f"Capturing on {interface} using {capture_method}...")
        
        # Start capture thread
        if capture_method == "scapy" and SCAPY_AVAILABLE:
            self.analyzer.capture_thread = threading.Thread(
                target=self.capture_packets_scapy, 
                args=(interface,), 
                daemon=True
            )
        else:
            self.analyzer.capture_thread = threading.Thread(
                target=self.capture_packets_socket, 
                daemon=True
            )
            
        self.analyzer.capture_thread.start()
        
    def capture_packets_scapy(self, interface):
        """Capture packets using Scapy"""
        try:
            sniff(iface=interface, prn=self.process_packet, stop_filter=lambda x: not self.analyzer.capturing)
        except Exception as e:
            error_msg = str(e)
            if "Operation not permitted" in error_msg or "Access is denied" in error_msg:
                error_msg = "Permission denied. Try running as Administrator/root or use socket method."
            self.root.after(0, lambda: messagebox.showerror("Capture Error", error_msg))
            self.root.after(0, self.stop_capture)
            
    def capture_packets_socket(self):
        """Capture packets using raw socket"""
        try:
            self.analyzer.monitor.start_capture_socket(self.process_packet)
        except Exception as e:
            error_msg = str(e)
            if "Operation not permitted" in error_msg or "Access is denied" in error_msg:
                error_msg = "Permission denied. Try running as Administrator/root."
            self.root.after(0, lambda: messagebox.showerror("Capture Error", error_msg))
            self.root.after(0, self.stop_capture)
        
    def stop_capture(self):
        """Stop packet capture"""
        self.analyzer.capturing = False
        self.analyzer.monitor.capturing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("Capture stopped")
        
    def process_packet(self, packet):
        """Process captured packet"""
        packet_info = self.analyzer.analyze_packet(packet)
        self.analyzer.packets.append(packet_info)
        
        # Update GUI in main thread
        self.root.after(0, self.add_packet_to_tree, packet_info)
        
    def add_packet_to_tree(self, packet_info):
        """Add packet to the tree view"""
        values = (
            packet_info['timestamp'],
            packet_info['src'],
            packet_info['dst'],
            packet_info['protocol'],
            packet_info['length'],
            packet_info['info']
        )
        
        self.packet_tree.insert('', tk.END, values=values)
        self.packet_count_var.set(f"Packets: {len(self.analyzer.packets)}")
        
        # Auto-scroll to bottom
        children = self.packet_tree.get_children()
        if children:
            self.packet_tree.see(children[-1])
        
    def on_packet_select(self, event):
        """Handle packet selection"""
        selection = self.packet_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        index = self.packet_tree.index(item)
        
        if index < len(self.analyzer.packets):
            packet_info = self.analyzer.packets[index]
            self.show_packet_details(packet_info)
            
    def show_packet_details(self, packet_info):
        """Display packet details"""
        # Clear previous details
        self.details_text.delete(1.0, tk.END)
        self.hex_text.delete(1.0, tk.END)
        
        # Show packet details
        details = f"Timestamp: {packet_info['timestamp']}\n"
        details += f"Source: {packet_info['src']}\n"
        details += f"Destination: {packet_info['dst']}\n"
        details += f"Protocol: {packet_info['protocol']}\n"
        details += f"Length: {packet_info['length']} bytes\n"
        details += f"Info: {packet_info['info']}\n\n"
        
        if SCAPY_AVAILABLE and 'raw_packet' in packet_info and hasattr(packet_info['raw_packet'], 'show'):
            try:
                packet = packet_info['raw_packet']
                details += "Layer Details:\n"
                details += packet.show(dump=True)
            except:
                details += "Could not parse packet layers\n"
        else:
            details += "Raw packet data available in hex dump\n"
                
        self.details_text.insert(1.0, details)
        
        # Show hex dump
        if 'raw_packet' in packet_info:
            try:
                if isinstance(packet_info['raw_packet'], bytes):
                    raw_data = packet_info['raw_packet']
                elif SCAPY_AVAILABLE and hasattr(packet_info['raw_packet'], '__bytes__'):
                    raw_data = bytes(packet_info['raw_packet'])
                else:
                    raw_data = str(packet_info['raw_packet']).encode()
                    
                hex_dump = self.create_hex_dump(raw_data)
                self.hex_text.insert(1.0, hex_dump)
            except Exception as e:
                self.hex_text.insert(1.0, f"Could not create hex dump: {e}")
                
    def create_hex_dump(self, data):
        """Create hex dump representation"""
        hex_dump = ""
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            
            # Offset
            hex_dump += f"{i:08x}  "
            
            # Hex values
            hex_values = []
            for j, byte in enumerate(chunk):
                if j == 8:
                    hex_values.append(" ")
                hex_values.append(f"{byte:02x}")
            hex_dump += " ".join(hex_values).ljust(49)
            
            # ASCII representation
            ascii_repr = ""
            for byte in chunk:
                if 32 <= byte <= 126:
                    ascii_repr += chr(byte)
                else:
                    ascii_repr += "."
            hex_dump += f"  |{ascii_repr}|\n"
            
        return hex_dump
        
    def clear_packets(self):
        """Clear all captured packets"""
        self.analyzer.packets.clear()
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        self.packet_count_var.set("Packets: 0")
        self.details_text.delete(1.0, tk.END)
        self.hex_text.delete(1.0, tk.END)
        
    def apply_filter(self):
        """Apply display filter"""
        filter_text = self.filter_var.get().lower()
        
        # Clear current display
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
            
        # Re-populate with filtered packets
        for packet_info in self.analyzer.packets:
            if not filter_text or self.packet_matches_filter(packet_info, filter_text):
                values = (
                    packet_info['timestamp'],
                    packet_info['src'],
                    packet_info['dst'],
                    packet_info['protocol'],
                    packet_info['length'],
                    packet_info['info']
                )
                self.packet_tree.insert('', tk.END, values=values)
                
    def packet_matches_filter(self, packet_info, filter_text):
        """Check if packet matches the filter"""
        searchable_text = f"{packet_info['src']} {packet_info['dst']} {packet_info['protocol']} {packet_info['info']}".lower()
        return filter_text in searchable_text
        
    def update_packet_list(self):
        """Periodic update of packet list"""
        self.root.after(1000, self.update_packet_list)

def check_admin():
    """Check if running with admin privileges"""
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:  # Linux/Unix
        return os.geteuid() == 0

def main():
    """Main function"""
    print("Network Analyzer Starting...")
    print(f"Scapy available: {SCAPY_AVAILABLE}")
    print(f"Psutil available: {PSUTIL_AVAILABLE}")
    print(f"Running as admin: {check_admin()}")
    
    if not check_admin():
        print("\nNote: For full packet capture capabilities:")
        if os.name == 'nt':
            print("- Run as Administrator (right-click -> 'Run as administrator')")
        else:
            print("- Run with sudo (sudo python network_analyzer.py)")
        print("- Or use the 'Generate Test Packets' button to see the interface in action")
    
    root = tk.Tk()
    app = NetworkAnalyzerGUI(root)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nShutting down...")
        if app.analyzer.capturing:
            app.stop_capture()

if __name__ == "__main__":
    main()