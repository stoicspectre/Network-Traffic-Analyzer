import csv
import json
import sys
from collections import Counter
from pathlib import Path


DEFAULT_THRESHOLD = 6


def load_traffic(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return list(csv.DictReader(file))
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        return None


def analyze_traffic(records, threshold):
    protocols = Counter()
    source_ips = Counter()
    destination_ports = Counter()
    total_bytes = 0

    for record in records:
        protocols[record["protocol"]] += 1
        source_ips[record["source_ip"]] += 1
        destination_ports[record["destination_port"]] += 1
        total_bytes += int(record["bytes"])

    suspicious_ips = {}

    for ip, count in source_ips.items():
        if count >= threshold:
            suspicious_ips[ip] = {
                "connections": count,
                "risk": "HIGH"
            }

    return {
        "total_connections": len(records),
        "total_bytes": total_bytes,
        "protocols": dict(protocols),
        "top_source_ips": dict(source_ips.most_common()),
        "top_destination_ports": dict(destination_ports.most_common()),
        "suspicious_ips": suspicious_ips
    }


def print_report(results, threshold):
    print("=" * 55)
    print("             NETWORK TRAFFIC ANALYZER")
    print("=" * 55)

    print(f"\nTotal connections: {results['total_connections']}")
    print(f"Total data: {results['total_bytes']} bytes")
    print(f"Detection threshold: {threshold}")

    print("\nProtocols:")

    for protocol, count in results["protocols"].items():
        print(f"  {protocol}: {count}")

    print("\nSource IPs:")

    for ip, count in results["top_source_ips"].items():
        print(f"  {ip}: {count}")

    print("\nDestination ports:")

    for port, count in results["top_destination_ports"].items():
        print(f"  {port}: {count}")

    print("\nSecurity alerts:")

    if not results["suspicious_ips"]:
        print("  [+] No suspicious activity detected.")
    else:
        for ip, data in results["suspicious_ips"].items():
            print("\n  [!] HIGH RISK")
            print(f"      IP: {ip}")
            print(f"      Connections: {data['connections']}")
            print(f"      Risk: {data['risk']}")

    print("\n" + "-" * 55)
    print("Analysis completed.")
    print("-" * 55)


def save_report(results):
    output_path = Path("reports/traffic_report.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=4)

    print(f"\n[+] Report saved to: {output_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("python3 traffic_analyzer.py <traffic_file> [threshold]")
        return

    traffic_file = sys.argv[1]

    if len(sys.argv) >= 3:
        try:
            threshold = int(sys.argv[2])
        except ValueError:
            print("[ERROR] Threshold must be a number.")
            return
    else:
        threshold = DEFAULT_THRESHOLD

    if threshold <= 0:
        print("[ERROR] Threshold must be greater than 0.")
        return

    records = load_traffic(traffic_file)

    if records is None:
        return

    results = analyze_traffic(records, threshold)

    print_report(results, threshold)
    save_report(results)


if __name__ == "__main__":
    main()