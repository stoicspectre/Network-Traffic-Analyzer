# Network-Traffic-Analyzer
A Python tool for analyzing network traffic data and detecting suspicious connection patterns
# 🌐 Network Traffic Analyzer

A Python-based educational tool for analyzing network traffic data and detecting suspicious connection patterns.

The project uses a fictional CSV dataset to demonstrate basic network security monitoring and traffic analysis.

## 🎯 Purpose

Network traffic analysis is an important part of cybersecurity.

Security analysts can examine information such as:

* Source IP addresses
* Destination IP addresses
* Ports
* Protocols
* Number of connections
* Amount of transferred data

This project demonstrates a simplified version of this process.

## ⚙️ Features

* CSV traffic analysis
* Protocol statistics
* Source IP analysis
* Destination port analysis
* Total connection count
* Total data calculation
* Suspicious IP detection
* Configurable detection threshold
* JSON security report
* Command-line interface
* No external Python packages

## 🛠️ Technologies

* Python 3
* `csv`
* `json`
* `collections`
* `pathlib`
* Git
* GitHub
* Visual Studio Code

## 📁 Project Structure

```text
Network-Traffic-Analyzer/
│
├── traffic_analyzer.py
├── traffic.csv
├── README.md
├── .gitignore
│
└── reports/
    └── traffic_report.json
```

## 🚀 Usage

Run the analyzer:

```bash
python3 traffic_analyzer.py traffic.csv
```

The default detection threshold is 6 connections.

A custom threshold can be provided:

```bash
python3 traffic_analyzer.py traffic.csv 4
```

## 📊 Example

Example traffic:

```text
Source IP       Destination Port    Protocol
192.168.1.10    443                 TCP
192.168.1.20    443                 TCP
192.168.1.30    53                  UDP
```

Example analysis:

```text
Total connections: 20

Protocols:
  TCP: 15
  UDP: 5

Destination ports:
  443: 10
  22: 4
  53: 4
  80: 2
```

## 🚨 Suspicious Activity Detection

The program counts connections from each source IP.

If an IP reaches the configured threshold, the program generates a security alert.

Example:

```text
[!] HIGH RISK
    IP: 192.168.1.20
    Connections: 9
    Risk: HIGH
```

This does not automatically mean that the IP is malicious.

A high number of connections can have many legitimate explanations.

## 🧠 How It Works

The program follows a simple analysis process:

```text
             CSV TRAFFIC
                  │
                  ▼
             CSV PARSER
                  │
                  ▼
           TRAFFIC ANALYSIS
                  │
       ┌──────────┼──────────┐
       ▼          ▼          ▼
   Protocols     IPs       Ports
       │          │          │
       └──────────┼──────────┘
                  ▼
           THRESHOLD CHECK
                  │
                  ▼
          SECURITY ALERT
                  │
                  ▼
             JSON REPORT
```

### 1. Load Data

The program reads the CSV file and converts every row into a traffic record.

### 2. Analyze Traffic

The program counts:

* Protocols
* Source IP addresses
* Destination ports
* Total connections
* Total transferred bytes

### 3. Detect Suspicious IPs

Source IP addresses are compared with the configured threshold.

### 4. Generate Report

The results are displayed in the terminal and saved as:

```text
reports/traffic_report.json
```

## 📚 Learning Goals

This project demonstrates:

* Network traffic analysis
* IP addresses
* TCP and UDP
* Network ports
* Traffic statistics
* Basic anomaly detection
* CSV processing
* JSON reporting
* Python data structures
* Defensive cybersecurity

## ⚠️ Limitations

This is a simplified educational project.

It does not capture real network packets and does not inspect packet contents.

The project currently works with a predefined CSV dataset.

A real network monitoring system can analyze much more information, including:

* Packet contents
* Connection duration
* DNS requests
* HTTP requests
* TLS information
* Geographic information
* Network flows
* Multiple devices
* Real-time traffic

The threshold-based detection used here can also produce false positives.

## 🔐 Ethical Use

This project is intended for educational and defensive cybersecurity purposes.

The included traffic data is fictional.

Do not capture, analyze, or inspect network traffic that you do not own or have permission to monitor.

## 🔮 Future Improvements

Possible improvements:

* Real-time traffic monitoring
* More detection rules
* Port scanning detection
* Connection-rate analysis
* Time-window analysis
* CSV export
* Graphs and statistics
* IP reputation checks
* Unit tests
* Network flow visualization

## 👨‍💻 Author

Personal cybersecurity learning project.
