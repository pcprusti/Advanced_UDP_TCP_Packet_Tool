# 📘 Advanced UDP/TCP Packet Tool

## 🛠 Overview
The Advanced UDP/TCP Packet Tool is a versatile desktop application for sending and receiving network packets over UDP and TCP. It’s designed for developers, testers, and engineers working with embedded systems, IoT devices, or custom protocols.

This tool supports hex mode, auto-repeat sending, real-time statistics, packet templates, saved profiles, and detailed logging. It also includes editable fields for source and destination IPs and ports, making it ideal for simulating traffic and testing routing scenarios.

---

## 🧭 Interface Breakdown

| Section              | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| **Destination IP**   | IP address of the target device/server you want to send packets to.         |
| **Source IP**        | IP address to bind locally when sending or receiving packets. Editable.     |
| **Destination Port** | Port number on the target device to send packets to.                        |
| **Source Port**      | Port number to listen on for incoming packets.                              |
| **Message**          | The packet content to send. Can be plain text or hex.                       |
| **Protocol**         | Choose between UDP or TCP for transmission.                                 |
| **Hex Mode**         | Toggle to send/receive data in hexadecimal format.                          |
| **Auto-Repeat**      | Automatically resend packets at a set interval.                             |
| **Output Window**    | Displays logs of sent and received packets.                                 |
| **Stats Panel**      | Shows real-time count of sent and received packets.                         |
| **Templates**        | Save/load/delete reusable packet messages.                                  |
| **Profiles**         | Save/load/delete full configurations (IP, ports, message, etc.).            |
| **Clear Output**     | Clears the reception window instantly.                                      |
| **Export Log**       | Saves the output window contents to a text file.                            |
| **About**            | Displays version and developer information.                                 |

---

## 🚀 Getting Started

### 1. Sending a Packet
- Enter the **Destination IP** and **Destination Port**.
- Optionally set a **Source IP**.
- Type your message in the **Message** field.
- Choose **UDP** or **TCP**.
- Enable **Hex Mode** if sending raw hex bytes.
- Click **Send Packet**.

### 2. Receiving Packets
- Enter the **Source Port** to listen on.
- Click **Start UDP Listener** or **Start TCP Listener**.
- Incoming packets will appear in the output window with source/destination info.

### 3. Auto-Repeat
- Set the interval (in seconds).
- Click **Start Auto-Repeat** to begin sending repeatedly.
- Click **Stop Auto-Repeat** to halt.

---

## 📦 Templates & Profiles

### Templates
- Save frequently used messages.
- Load them instantly into the Message field.
- Great for testing repeated payloads.

### Profiles
- Save full configurations (IP, ports, message, protocol, hex mode).
- Load them to quickly switch between test setups.

---

## 🧹 Maintenance Tools

- **Clear Output**: Wipe the reception window.
- **Export Log**: Save all logs to `exported_log.txt` for analysis or documentation.
- **About**: View version and developer info.

---

## 🧠 Tips & Best Practices

- Use **Hex Mode** when working with binary protocols like Modbus or MQTT.
- Always verify your IP and port settings before sending.
- Save profiles for different devices or test cases.
- Use **Auto-Repeat** with caution—some devices may not handle rapid traffic well.

