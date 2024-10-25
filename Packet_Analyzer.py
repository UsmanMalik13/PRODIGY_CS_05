import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP, UDP, Ether
import threading

# Initialize the main window
root = tk.Tk()
root.title("Network Packet Analyzer")
root.geometry("800x450")

# Set up the text area to display packet information
text_area = scrolledtext.ScrolledText(root, width=100, height=20, wrap=tk.WORD)
text_area.pack(pady=10)

# Variables to control sniffing
sniffing_thread = None
is_sniffing = False

# Function to simplify protocol descriptions
def get_protocol_name(packet):
    if packet.haslayer(TCP):
        return "TCP (Reliable Transmission)"
    elif packet.haslayer(UDP):
        return "UDP (Fast, No Confirmation)"
    else:
        return "Other"

# Function to process each packet
def process_packet(packet):
    if packet.haslayer(IP):
        # Get packet information
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol_name = get_protocol_name(packet)
        payload = packet[IP].payload.original[:50] if packet[IP].payload else b"No Payload Data"

        # Simplify payload for readability
        payload_text = payload.decode(errors="ignore") if payload else "No Content"
        
        # Friendly text for non-technical users
        packet_info = (
            f"📡 **New Packet Captured!**\n\n"
            f"🟢 **From:** {src_ip} (Sender's IP Address)\n"
            f"🔵 **To:** {dst_ip} (Receiver's IP Address)\n"
            f"📌 **Protocol Used:** {protocol_name} - This defines the way data is structured.\n"
            f"📄 **Payload Summary:** {payload_text} - This is the packet's message content (first 50 characters).\n\n"
            "====================================\n\n"
        )

        # Display packet information in the text area
        text_area.insert(tk.END, packet_info)
        text_area.see(tk.END)  # Scroll to the end

# Function to start sniffing packets
def start_sniffing():
    global is_sniffing, sniffing_thread
    if not is_sniffing:
        is_sniffing = True
        sniffing_thread = threading.Thread(target=sniff_packets, daemon=True)
        sniffing_thread.start()

def sniff_packets():
    sniff(prn=process_packet, store=False, stop_filter=lambda x: not is_sniffing)

# Function to stop sniffing packets
def stop_sniffing():
    global is_sniffing
    is_sniffing = False

# Start and Stop buttons
start_button = tk.Button(root, text="Start Analysis", command=start_sniffing, bg="green", fg="white", width=15)
start_button.pack(pady=5)

stop_button = tk.Button(root, text="Stop Analysis", command=stop_sniffing, bg="red", fg="white", width=15)
stop_button.pack(pady=5)

# Start the tkinter main loop
root.mainloop()
