# 🧠 Network Analyzer GUI (Python + Scapy)

A cross-platform, GUI-based network packet analyzer built with **Tkinter**, powered by **Scapy** and raw **socket** fallback. Supports real-time packet capture, detailed analysis, and hex dump viewing.

![image](https://github.com/user-attachments/assets/ef088344-3c7e-4be6-9412-1fc75e84912d)

---

## 📦 Features

- 📡 Real-time packet sniffing
- 🔍 Protocol support: **TCP**, **UDP**, **HTTP**, **HTTPS**, **DNS**, **ICMP**, **ARP**
- 🧾 Live GUI using **Tkinter**
- 🧵 Multithreaded packet capture
- 🧪 Built-in test packet generation (no network required)
- 🧱 Hex dump viewer
- 🔎 Filter packets by keywords

---

## 🖥️ GUI Overview

- **Interface Selection**: Choose your network adapter (e.g., `eth0`, `Wi-Fi`)
- **Capture Method**:
  - `auto` – chooses Scapy if available
  - `scapy` – advanced packet parsing
  - `socket` – fallback using raw sockets
- **Live Packet List**: View real-time packets in a table
- **Packet Details**: Shows protocol, ports, TTL, info
- **Hex Dump Tab**: View raw bytes in hex + ASCII
- **Test Packets**: Use without needing an active network

---

## ✅ Requirements

Install the required Python packages:

```bash
pip install scapy psutil
```

> **Note**: You need administrator/root privileges to capture packets from real interfaces.

---

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/Kalharapasan/Network-Analyzer-V02-Python.git
cd Network-Analyzer-V02-Python
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install scapy psutil
```

### 3. Run the application

#### 🪟 On Windows (as Administrator):

```bash
python main.py
```

#### 🐧 On Linux/macOS:

```bash
sudo python3 main.py
```

> Use the “Generate Test Packets” button to try out the app without root privileges.

---

## 📁 File Structure

```bash
main.py           # Main application file
README.md         # This file
requirements.txt  # Dependency list
```

---

## ⚠️ Permissions & Limitations

- Admin/Root required for capturing real traffic.
- If Scapy is not installed or blocked, the app falls back to raw sockets.
- On Windows, run CMD as Administrator.
- On Linux/macOS, use sudo.

---

## 🧪 Example Test Packet Display

| Time       | Source        | Destination | Protocol | Length | Info                         |
|------------|---------------|-------------|----------|--------|------------------------------|
| 12:34:56.7 | 192.168.1.1   | 8.8.8.8     | DNS      | 64     | DNS Query: example.com       |
| 12:34:58.1 | 192.168.1.100 | 8.8.8.8     | TCP      | 1024   | Port 12345 → 80 (HTTP)       |

---

## 📄 License

📄 [License](./LICENSE.md): Proprietary – Permission Required

---

## 🙋‍♀️ Contributing

Contributions, bug reports, and pull requests are welcome!

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/foo`)
3. Commit your changes (`git commit -am 'Add cool feature'`)
4. Push to the branch (`git push origin feature/foo`)
5. Open a Pull Request

---

## 🔗 Credits

Built with ❤️ using Python, Scapy, and Tkinter

