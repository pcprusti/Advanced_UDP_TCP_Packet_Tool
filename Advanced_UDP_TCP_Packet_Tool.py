import socket
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
import json
import os
from tkinter import messagebox


# ========== Globals ==========
auto_repeat = False
packet_sent_count = 0
packet_received_count = 0
udp_listener_running = False
tcp_listener_running = False

TEMPLATE_FILE = "templates.json"
PROFILE_FILE  = "profiles.json"

# ========== Storage Helpers ==========
def ensure_files():
    if not os.path.exists(TEMPLATE_FILE):
        with open(TEMPLATE_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f, indent=2)
    if not os.path.exists(PROFILE_FILE):
        with open(PROFILE_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f, indent=2)

def load_templates_dict():
    ensure_files()
    with open(TEMPLATE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_templates_dict(d):
    with open(TEMPLATE_FILE, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2)

def load_profiles_dict():
    ensure_files()
    with open(PROFILE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_profiles_dict(d):
    with open(PROFILE_FILE, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2)

# ========== UI Helpers ==========
def log(message):
    timestamp = time.strftime("%H:%M:%S")
    output_box.insert(tk.END, f"[{timestamp}] {message}\n")
    output_box.see(tk.END)

def update_dashboard():
    stats_label.config(text=f"Sent: {packet_sent_count} | Received: {packet_received_count}")

# ========== Networking ==========
def send_packet():
    global packet_sent_count
    dest_ip = dest_ip_entry.get().strip()
    protocol = protocol_var.get()
    hex_mode = hex_var.get()
    message = message_entry.get()

    # Validate Destination Port
    try:
        port = int(destination_port_entry.get())
        if not (1 <= port <= 65535):
            raise ValueError
    except ValueError:
        log("Invalid Destination Port. Use 1-65535.")
        return

    if not dest_ip:
        log("Destination IP is required.")
        return

    try:
        if hex_mode:
            try:
                data = bytes.fromhex(message.replace(" ", ""))
            except ValueError:
                log("Invalid hex string. Example: '48 65 6C 6C 6F'")
                return
        else:
            data = message.encode()

        if protocol == "UDP":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(data, (dest_ip, port))
            sock.close()
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((dest_ip, port))
            sock.sendall(data)
            sock.close()

        packet_sent_count += 1
        update_dashboard()
        display_msg = message.upper() if hex_mode else message
        log(f"Sent ({protocol}) to {dest_ip}:{port}: {display_msg}")
    except Exception as e:
        log(f"Error: {e}")

def start_auto_repeat():
    global auto_repeat
    try:
        float(interval_entry.get())
    except ValueError:
        log("Invalid auto-repeat interval.")
        return
    auto_repeat = True
    threading.Thread(target=repeat_sender, daemon=True).start()
    log("Auto-repeat started.")

def stop_auto_repeat():
    global auto_repeat
    auto_repeat = False
    log("Auto-repeat stopped.")

def repeat_sender():
    try:
        interval = float(interval_entry.get())
    except ValueError:
        interval = 1.0
    while auto_repeat:
        send_packet()
        time.sleep(interval)

def start_udp_listener():
    global udp_listener_running
    if udp_listener_running:
        log("UDP listener already running.")
        return
    # Validate listen port
    try:
        port = int(source_port_entry.get())
        if not (1 <= port <= 65535):
            raise ValueError
    except ValueError:
        log("Invalid Listen Port. Use 1-65535.")
        return
    udp_listener_running = True
    threading.Thread(target=udp_listen, daemon=True).start()

def stop_udp_listener():
    global udp_listener_running
    if udp_listener_running:
        udp_listener_running = False
    else:
        log("UDP listener not running.")

def udp_listen():
    global packet_received_count
    port = int(source_port_entry.get())
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("", port))
        sock.settimeout(1.0)
        log(f"UDP listener started on port {port}")
        while udp_listener_running:
            try:
                data, addr = sock.recvfrom(65535)
                source_ip = addr[0]
                source_ip_var.set(source_ip)
                dest_ip = dest_ip_entry.get()
                msg = data.hex().upper() if hex_var.get() else data.decode(errors="ignore")
                packet_received_count += 1
                update_dashboard()
                log(f"Received UDP packet\nSource IP: {source_ip}\nDestination IP: {dest_ip}\nData: {msg}")
            except socket.timeout:
                continue
        sock.close()
        log("UDP listener stopped.")
    except Exception as e:
        log(f"UDP Listener error: {e}")

def start_tcp_listener():
    global tcp_listener_running
    if tcp_listener_running:
        log("TCP listener already running.")
        return
    # Validate listen port
    try:
        port = int(source_port_entry.get())
        if not (1 <= port <= 65535):
            raise ValueError
    except ValueError:
        log("Invalid Listen Port. Use 1-65535.")
        return
    tcp_listener_running = True
    threading.Thread(target=tcp_listen, daemon=True).start()

def stop_tcp_listener():
    global tcp_listener_running
    if tcp_listener_running:
        tcp_listener_running = False
    else:
        log("TCP listener not running.")

def tcp_listen():
    global packet_received_count
    port = int(source_port_entry.get())
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("", port))
        sock.listen(5)
        sock.settimeout(1.0)
        log(f"TCP listener started on port {port}")
        while tcp_listener_running:
            try:
                conn, addr = sock.accept()
                source_ip = addr[0]
                source_ip_var.set(source_ip)
                dest_ip = dest_ip_entry.get()
                # Read possibly multiple chunks
                conn.settimeout(1.0)
                chunks = []
                try:
                    while True:
                        chunk = conn.recv(65535)
                        if not chunk:
                            break
                        chunks.append(chunk)
                except socket.timeout:
                    pass
                data = b"".join(chunks)
                conn.close()
                if data:
                    msg = data.hex().upper() if hex_var.get() else data.decode(errors="ignore")
                    packet_received_count += 1
                    update_dashboard()
                    log(f"Received TCP packet\nSource IP: {source_ip}\nDestination IP: {dest_ip}\nData: {msg}")
            except socket.timeout:
                continue
        sock.close()
        log("TCP listener stopped.")
    except Exception as e:
        log(f"TCP Listener error: {e}")

# ========== Export ==========
def export_log():
    try:
        with open("exported_log.txt", "w", encoding="utf-8") as f:
            f.write(output_box.get("1.0", tk.END))
        log("Log exported to exported_log.txt")
    except Exception as e:
        log(f"Export error: {e}")

# ========== Templates ==========
def refresh_template_menu():
    d = load_templates_dict()
    template_menu["values"] = sorted(d.keys())

def load_template():
    name = template_var.get().strip()
    if not name:
        log("Select or type a template name to load.")
        return
    d = load_templates_dict()
    if name in d:
        message_entry.delete(0, tk.END)
        message_entry.insert(0, d[name])
        log(f"Template '{name}' loaded.")
    else:
        log(f"Template '{name}' not found.")

def save_template():
    name = template_var.get().strip()
    if not name:
        log("Enter a template name to save.")
        return
    d = load_templates_dict()
    d[name] = message_entry.get()
    save_templates_dict(d)
    refresh_template_menu()
    log(f"Template '{name}' saved.")

def delete_template():
    name = template_var.get().strip()
    if not name:
        log("Enter/select a template name to delete.")
        return
    d = load_templates_dict()
    if name in d:
        del d[name]
        save_templates_dict(d)
        refresh_template_menu()
        log(f"Template '{name}' deleted.")
    else:
        log(f"Template '{name}' not found.")

# ========== Profiles ==========
def refresh_profile_menu():
    d = load_profiles_dict()
    profile_menu["values"] = sorted(d.keys())

def load_profile():
    name = profile_var.get().strip()
    if not name:
        log("Select or type a profile name to load.")
        return
    d = load_profiles_dict()
    if name in d:
        p = d[name]
        dest_ip_entry.delete(0, tk.END); dest_ip_entry.insert(0, p.get("dest_ip", ""))
        source_ip_entry.delete(0, tk.END); source_ip_entry.insert(0, p.get("dest_ip",""))
        destination_port_entry.delete(0, tk.END); destination_port_entry.insert(0, p.get("destination_port", ""))
        source_port_entry.delete(0, tk.END); source_port_entry.insert(0, p.get("source_port", ""))
        message_entry.delete(0, tk.END); message_entry.insert(0, p.get("message", ""))
        protocol_var.set(p.get("protocol", ""))
        hex_var.set(bool(p.get("hex", False)))
        log(f"Profile '{name}' loaded.")
    else:
        log(f"Profile '{name}' not found.")

def save_profile():
    name = profile_var.get().strip()
    if not name:
        log("Enter a profile name to save.")
        return
    d = load_profiles_dict()
    d[name] = {
        "dest_ip": dest_ip_entry.get(),
        "source_ip": source_ip_entry.get(),
        "destination_port": destination_port_entry.get(),
        "source_port": source_port_entry.get(),
        "message": message_entry.get(),
        "protocol": protocol_var.get(),
        "hex": bool(hex_var.get())
    }
    save_profiles_dict(d)
    refresh_profile_menu()
    log(f"Profile '{name}' saved.")

def delete_profile():
    name = profile_var.get().strip()
    if not name:
        log("Enter/select a profile name to delete.")
        return
    d = load_profiles_dict()
    if name in d:
        del d[name]
        save_profiles_dict(d)
        refresh_profile_menu()
        log(f"Profile '{name}' deleted.")
    else:
        log(f"Profile '{name}' not found.")

def clear_output():
    output_box.delete("1.0", tk.END)
    log("Reception window cleared.")

def show_about():
    about_text = (
        "Advanced UDP/TCP Packet Tool\n"
        "Version: 1.0.0\n"
        "Developer: Purna Chandra Prusti\n"
        "© 2025 All rights reserved."
    )
    messagebox.showinfo("About", about_text)


# ========== GUI ==========
root = tk.Tk()
root.title("Advanced UDP/TCP Packet Tool")

menu_bar = tk.Menu(root)
help_menu = tk.Menu(menu_bar, tearoff=0)
help_menu.add_command(label="About", command=show_about)
menu_bar.add_cascade(label="Help", menu=help_menu)
root.config(menu=menu_bar)

# Stretch columns
for c in range(4):
    root.grid_columnconfigure(c, weight=1)

# Row 0: Destination & Source IP
tk.Label(root, text="Destination IP:").grid(row=0, column=0, sticky="e")
dest_ip_entry = tk.Entry(root)
dest_ip_entry.insert(0, "")
dest_ip_entry.grid(row=0, column=1, sticky="we")

tk.Label(root, text="Source IP:").grid(row=0, column=2, sticky="e")
source_ip_var = tk.StringVar()
source_ip_entry = tk.Entry(root, textvariable=source_ip_var)
source_ip_entry.grid(row=0, column=3, sticky="we")

# Row 1: Ports
tk.Label(root, text="Destination Port:").grid(row=1, column=0, sticky="e")
destination_port_entry = tk.Entry(root)
destination_port_entry.insert(0, "")
destination_port_entry.grid(row=1, column=1, sticky="we")

tk.Label(root, text="Source Port:").grid(row=1, column=2, sticky="e")
source_port_entry = tk.Entry(root)
source_port_entry.insert(0, "")
source_port_entry.grid(row=1, column=3, sticky="we")

# Row 2: Message
tk.Label(root, text="Message:").grid(row=2, column=0, sticky="e")
message_entry = tk.Entry(root)
message_entry.grid(row=2, column=1, columnspan=3, sticky="we")

# Row 3: Protocol
tk.Label(root, text="Protocol:").grid(row=3, column=0, sticky="e")
protocol_var = tk.StringVar(value="UDP")
protocol_menu = ttk.Combobox(root, textvariable=protocol_var, values=["UDP", "TCP"], state="readonly")
protocol_menu.grid(row=3, column=1, sticky="we")

# Row 4: Hex Mode
hex_var = tk.BooleanVar(value=False)
tk.Checkbutton(root, text="Hex Mode", variable=hex_var).grid(row=4, column=0, sticky="w")
tk.Label(root, text="(Hex example: '48 65 6C 6C 6F')", fg="gray").grid(row=4, column=1, sticky="w")

# Row 5: Auto-repeat
tk.Label(root, text="Auto-Repeat Interval (s):").grid(row=5, column=0, sticky="e")
interval_entry = tk.Entry(root)
interval_entry.insert(0, "1")
interval_entry.grid(row=5, column=1, sticky="we")

# Row 6: Actions
tk.Button(root, text="Send Packet", command=send_packet).grid(row=6, column=0, pady=4, sticky="we")
tk.Button(root, text="Start Auto-Repeat", command=start_auto_repeat).grid(row=6, column=1, pady=4, sticky="we")
tk.Button(root, text="Stop Auto-Repeat", command=stop_auto_repeat).grid(row=6, column=2, pady=4, sticky="we")
tk.Button(root, text="Export Log", command=export_log).grid(row=6, column=3, pady=4, sticky="we")

# Row 7: Listeners
tk.Button(root, text="Start UDP Listener", command=start_udp_listener).grid(row=7, column=0, pady=4, sticky="we")
tk.Button(root, text="Stop UDP Listener", command=stop_udp_listener).grid(row=7, column=1, pady=4, sticky="we")
tk.Button(root, text="Start TCP Listener", command=start_tcp_listener).grid(row=7, column=2, pady=4, sticky="we")
tk.Button(root, text="Stop TCP Listener", command=stop_tcp_listener).grid(row=7, column=3, pady=4, sticky="we")
tk.Button(root, text="Clear Output", command=clear_output).grid(row=6, column=3, pady=4, sticky="we")

# Row 8: Output
output_box = scrolledtext.ScrolledText(root, width=90, height=18)
output_box.grid(row=8, column=0, columnspan=4, pady=6, sticky="nsew")
root.grid_rowconfigure(8, weight=1)

# Row 9: Stats
stats_label = tk.Label(root, text="Sent: 0 | Received: 0")
stats_label.grid(row=9, column=0, columnspan=4, sticky="we")

# Row 10-12: Templates
tk.Label(root, text="Template:").grid(row=10, column=0, sticky="e")
template_var = tk.StringVar()
template_menu = ttk.Combobox(root, textvariable=template_var, values=[], state="normal")
template_menu.grid(row=10, column=1, sticky="we")
tk.Button(root, text="Load Template", command=load_template).grid(row=10, column=2, sticky="we")
tk.Button(root, text="Save Template", command=save_template).grid(row=10, column=3, sticky="we")
tk.Button(root, text="Delete Template", command=delete_template).grid(row=11, column=3, sticky="we")

# Row 11-13: Profiles
tk.Label(root, text="Profile:").grid(row=11, column=0, sticky="e")
profile_var = tk.StringVar()
profile_menu = ttk.Combobox(root, textvariable=profile_var, values=[], state="normal")
profile_menu.grid(row=11, column=1, sticky="we")
tk.Button(root, text="Load Profile", command=load_profile).grid(row=11, column=2, sticky="we")
tk.Button(root, text="Save Profile", command=save_profile).grid(row=12, column=2, sticky="we")
tk.Button(root, text="Delete Profile", command=delete_profile).grid(row=12, column=3, sticky="we")

# Init storage/dropdowns
ensure_files()
refresh_template_menu()
refresh_profile_menu()

# Start GUI
root.minsize(900, 560)
root.mainloop()
