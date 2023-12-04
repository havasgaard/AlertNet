# Didrik Havasgaard
from scapy.all import sniff, TCP, UDP, IP, Raw, DNS
from collections import Counter
from threading import Thread
import queue
import logging

# Set up basic logging
logging.basicConfig(filename='alertnet_logs.log',
                    filemode='a',
                    format='%(asctime)s - %(message)s',  # Corrected here
                    level=logging.INFO)


# Global packet queue
packet_queue = queue.Queue()

# SSH Analysis Function
ssh_attempts = Counter()


def analyze_ssh(packet):  # Analyze SSH packets for potential brute force attacks.
    if packet[TCP].dport == 22:
        src_ip = packet[IP].src
        ssh_attempts[src_ip] += 1
        if ssh_attempts[src_ip] > 5:  # Threshold for brute force attempt
            alert = f"Possible SSH brute force attack from {src_ip}"
            print(alert)
            logging.warning(alert)


# HTTP/HTTPS Analysis Function
def analyze_http_https(packet):  # Analyze HTTP and HTTPS for potential threats
    if packet.haslayer(TCP) and packet[TCP].dport == 80:  # Only HTTP traffic
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        packet_size = len(packet)
        tcp_flags = packet.sprintf('%TCP.flags%')

        alert = (f"HTTP traffic detected from {src_ip}:{src_port} to {dst_ip}:{dst_port}, "
                 f"Packet size: {packet_size} bytes, TCP Flags: {tcp_flags}")

        print(alert)
        logging.info(alert)


# DNS Analysis Function
def analyze_dns(packet):  # Analyze DNS traffic
    if packet.haslayer(UDP) and packet[UDP].dport == 53 and packet.haslayer(DNS):
        dns_query = packet[DNS].qd.qname if packet[DNS].qd else 'Unknown'
        alert = f"DNS query detected: {dns_query}"
        print(alert)
        logging.info(alert)


# Packet Callback Function
def packet_callback(packet):  # Directs packets to analysis based on type
    if packet.haslayer(TCP):
        if packet[TCP].dport == 22:
            analyze_ssh(packet)
        elif packet[TCP].dport in [80, 443]:
            analyze_http_https(packet)

    if packet.haslayer(UDP):
        if packet[UDP].dport == 53:
            analyze_dns(packet)


# Packet Processing Function for the Thread
def process_packets():
    """
    Processes packets from the queue in a separate thread.
    """
    while True:
        packet = packet_queue.get()
        if packet is None:  # Check for termination signal
            break
        packet_callback(packet)  # Using the existing callback for processing
        packet_queue.task_done()


# Main Function
def main():
    print("Starting AlertNet...")

    # Start the packet processing thread
    processing_thread = Thread(target=process_packets)
    processing_thread.start()

    # Packet sniffing
    sniff(prn=lambda packet: packet_queue.put(packet), store=0)

    # Cleanup and termination
    packet_queue.put(None)  # Signal to terminate the processing thread
    processing_thread.join()


if __name__ == "__main__":
    main()
