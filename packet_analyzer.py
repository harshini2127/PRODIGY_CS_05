import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog
from datetime import datetime
import csv
from scapy.all import *
import threading

packet_count=0
all_packets=[]
sniffing=False

def process_packet(packet):
    
    if IP in packet:
        
        #print("----------------------")
        #global packet_count
        #packet_count+=1
        #print(packet_count)
        #print("source ip address:",packet[IP].src)
        #print("destination ip address:",packet[IP].dst)
        if packet[IP].proto==6:
            protocol="TCP"
        elif packet[IP].proto==17:
            protocol="UDP"
        elif packet[IP].proto==1:
            protocol="ICMP"
        else:
            protocol="OTHER"
        
        if protocol == "TCP":
            tag = "tcp"

        elif protocol == "UDP":
            tag = "udp"

        elif protocol == "ICMP":
            tag = "icmp"

        else:
            tag = "other"
        
        global packet_count
        packet_count+=1
        counter_label.config(
            text=f"Packets Captured: {packet_count}"
        )
        if Raw in packet:
            payload=packet[Raw].load
            
            payload=payload.decode(errors="ignore")
            payload = payload.replace("\n", " ")
            payload = payload.replace("\r", " ")
            if not payload.isprintable():
                payload = "Binary/Encrypted Data"
            payload = payload[:40]
            
        else:
            payload="No payload"

        packet_info={"packet_no":packet_count,
                     "timestamp":datetime.now().strftime("%H:%M:%S"),
                    "source_ip_address":packet[IP].src,
                    "destination_ip_address":packet[IP].dst,
                    "protocol":protocol,
                    "payload":payload}
        all_packets.append(packet_info)
        item=packet_table.insert(
            "",
            "end",
            values=(
                packet_info["packet_no"],
                packet_info["timestamp"],
                packet_info["source_ip_address"],
                packet_info["destination_ip_address"],
                packet_info["protocol"],
                packet_info["payload"]
            ),
            tags=(tag,)
        )
        packet_table.see(item)

#start sniffing function  
def start_sniffing():
    sniff(
    prn=process_packet,
    stop_filter=lambda packet: not sniffing
)

def start_thread():
    global sniffing
    sniffing = True
    status_label.config(
        text="Status: Sniffing...",
        fg="light green"
    )
    thread = threading.Thread(
        target = start_sniffing,
        daemon = True
    )
    thread.start()

#stop sniffing function
def stop_sniffing():
    global sniffing
    sniffing = False
    status_label.config(
        text="Status: Stopped Sniffing",
        fg="orange"
    )

#filtering packets funtion
def filter_packets(event):
    filtered_count=0
    selected_protocol=protocol_filter.get()
    for item in packet_table.get_children():
        packet_table.delete(item)
    for packet in all_packets:
        if selected_protocol == "ALL" or packet["protocol"] == selected_protocol:
            filtered_count+=1
            if packet["protocol"] == "TCP":
                tag = "tcp"

            elif packet["protocol"] == "UDP":
                tag = "udp"

            elif packet["protocol"] == "ICMP":
                tag = "icmp"

            else:
                tag = "other"
            item = packet_table.insert(
                "",
                "end",
                values=(
                    packet["packet_no"],
                    packet["timestamp"],
                    packet["source_ip_address"],
                    packet["destination_ip_address"],
                    packet["protocol"],
                    packet["payload"]
                ),
                tags=(tag,)
            )
            
            packet_table.see(item)
    counter_label.config(
        text=f"Packets Captured: {filtered_count}"
    )

#clear packet function
def clear_packets():
    status_label.config(
    text="Status: Clearing Data...",
    fg="cyan"
    )
    for item in packet_table.get_children():
        packet_table.delete(item)
    all_packets.clear()
    global packet_count
    packet_count=0
    counter_label.config(
        text="Packets Captured: 0"
    )
    status_label.config(
    text="Status: Data Cleared",
    fg="yellow"
    )
  
#export packet function
def export_packets():
    status_label.config(
    text="Status: Exporting Data...",
    fg="cyan"
    )
    file_path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV Files", "*.csv")],
        initialfile="packets.csv"
    )
    if file_path:
        with open(file_path, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["packet_no","source_ip","destination_ip","protocol","payload"])
            for packet in all_packets:
                writer.writerow([ packet["packet_no"],
                    packet["timestamp"],             
                    packet["source_ip_address"],
                    packet["destination_ip_address"],
                    packet["protocol"], 
                    packet["payload"]])
        messagebox.showinfo(
            "Success",
            "File Saved Successfully"
        )  
        status_label.config(
            text="Status: Data Exported Successfully",
            fg="light blue"
        )

#GUI
root = tk.Tk()
root.title("Network packet analyzer")
root.state("zoomed")
root.configure(bg="#1E1E1E")
heading= tk.Label(
    root,
    text="🔐 Network Packet Analyzer",
    font=("consolas", 30, "bold"),
    bg="#1E1E1E",
    fg="white",
    padx=10,
    pady=10

)
heading.pack(pady=15)

main_frame = tk.Frame(
    root,
    bg="#2D2D2D",
    padx=30,
    pady=30,
    bd=3,
    highlightbackground="gray30",
    highlightthickness=1
)

main_frame.pack(
    fill="both",
    expand=True,
    padx=40,
    pady=10
)

control_frame=tk.Frame(
    main_frame,
    bg="#2D2D2D"

)
control_frame.pack(
    padx=40,
    pady=10
)

start_button = tk.Button(
    control_frame,
    text="Start Sniffing",
    font=("Consolas", 13, "bold"),
    bg="#00AA00",
    fg="white",
    activebackground="darkgreen",
    activeforeground="white",
    relief="flat",
    bd=0,
    cursor="hand2",
    width=18,
    pady=10,
    command=start_thread
)
start_button.grid(
    row=0,
    column=0,
    padx=25,
    pady=10
)

stop_button = tk.Button(
    control_frame,
    text="Stop Sniffing",
    font=("Consolas", 13, "bold"),
    bg="#CC0000",
    fg="white",
    activebackground="darkred",
    activeforeground="white",
    relief="flat",
    bd=0,
    cursor="hand2",
    width=18,
    pady=10,
    command=stop_sniffing
)
stop_button.grid(
    row=0,
    column=1,
    padx=20,
    pady=10
)

counter_label = tk.Label(
    control_frame,
    text="Packets Captured: 0",
    font=("consolas", 14, "bold"),
    bg="#2D2D2D",
    fg="light green",
    width=30,
    anchor="w"
)

counter_label.grid(
    row=0,
    column=2,
    padx=20,
    pady=10
)

filter_label = tk.Label(
    control_frame,
    text="Protocol Filter:",
    font=("consolas", 14, "bold"),
    bg="#2D2D2D",
    fg="white"
)

filter_label.grid(
    row=0,
    column=3,
    padx=10,
    pady=10
)

protocol_filter = ttk.Combobox(
    control_frame,
    values=["ALL", "TCP", "UDP", "ICMP", "OTHER"],
    font=("consolas", 12),
    width=12,
    state="readonly"
)

protocol_filter.set("ALL")

protocol_filter.grid(
    row=0,
    column=4,
    padx=10,
    pady=10
)
protocol_filter.bind(
    "<<ComboboxSelected>>",
    filter_packets
)

table_frame = tk.Frame(
    main_frame,
    bg="#2D2D2D"
)

table_frame.pack(
    fill="both",
    expand=True,
    pady=5
)
bottom_frame= tk.Frame (
    main_frame,
    bg="#2D2D2D",
)
bottom_frame.pack(
    fill="x",
    pady=10
)
bottom_frame.columnconfigure(0, weight=1)
bottom_frame.columnconfigure(1, weight=1)
bottom_frame.columnconfigure(2, weight=1)
status_label=tk.Label(
    bottom_frame,
    text="Status:Ready to Sniff",
    font=("consolas", 15, "bold"),
    width=35,
    bg="#2D2D2D",
    fg="white"
    
)
status_label.grid(
    row=0,
    column=0,
    padx=10,
    pady=10
)
clear_button = tk.Button(
    bottom_frame,
    text="Clear Data",
    font=("Consolas", 13, "bold"),
    bg="#FF9900",
    fg="white",
    activebackground="#CC7700",
    activeforeground="white",
    relief="flat",
    bd=0,
    cursor="hand2",
    width=18,
    pady=8,
    command=clear_packets
)
clear_button.grid(
    row=0,
    column=1,
    padx=10,
    pady=10
)
export_button = tk.Button(
    bottom_frame,
    text="Export Data",
    font=("Consolas", 13, "bold"),
    bg="#0066FF",
    fg="white",
    activebackground="#0044AA",
    activeforeground="white",
    relief="flat",
    bd=0,
    cursor="hand2",
    width=18,
    pady=8,
    command=export_packets
)
export_button.grid(
    row=0,
    column=2,
    padx=10,
    pady=10
)
scrollbar = tk.Scrollbar(
    table_frame
)
style = ttk.Style()
style.theme_use("default")
style.configure(
    "Treeview",
    background="#161B22",
    foreground="white",
    fieldbackground="#161B22",
    rowheight=28,
    font=("Consolas", 11)
)
style.configure(
    "Treeview.Heading",
    background="black",
    foreground="cyan",
    font=("Consolas", 12, "bold")
)
style.map(
    "Treeview",
    background=[("selected", "cyan")],
    foreground=[("selected", "black")]
)
packet_table = ttk.Treeview(
    table_frame,
    columns=("packet_no", "timestamp","source_ip", "destination_ip", "protocol","payload"),
    show="headings",
    yscrollcommand=scrollbar.set,
    height=8
)
packet_table.tag_configure(
    "tcp",
    background="#16351F"
)
packet_table.tag_configure(
    "udp",
    background="#3A2A16"
)
packet_table.tag_configure(
    "icmp",
    background="#16263A"
)
packet_table.tag_configure(
    "other",
    background="#2A2A2A"
)
scrollbar.config(
    command=packet_table.yview
)
scrollbar.pack(
    side="right",
    fill="y"
)
packet_table.heading("packet_no", text="Packet No")
packet_table.heading("timestamp", text="Time")
packet_table.heading("source_ip", text="Source IP")
packet_table.heading("destination_ip", text="Destination IP")
packet_table.heading("protocol", text="Protocol")
packet_table.heading("payload", text="Payload")
packet_table.column("packet_no", width=100)
packet_table.column("timestamp", width=100)
packet_table.column("source_ip", width=200)
packet_table.column("destination_ip", width=200)
packet_table.column("protocol", width=100)
packet_table.column("payload", width=450)
packet_table.pack(
    fill="x",
    expand=True
)
root.mainloop()