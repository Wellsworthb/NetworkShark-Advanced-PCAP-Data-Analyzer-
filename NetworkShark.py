import hashlib
import os
import re
import logging
import pyshark
import matplotlib.pyplot as plt

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def analyze_logs(log_file_path, pattern, encoding='utf-16-le'):
    """Analyzes a log file for specific patterns."""
    logging.info(f"Attempting to open log file at: {log_file_path}")
    if not os.path.exists(log_file_path):
        logging.error("Log file does not exist.")
        return ["Log file does not exist."]

    found_items = []
    pattern_compiled = re.compile(pattern)
    try:
        with open(log_file_path, 'rt', encoding=encoding) as file:
            for line in file:
                if pattern_compiled.search(line):
                    found_items.append(line.strip())
    except FileNotFoundError:
        logging.error("The log file was not found.")
        return ["Log file was not found."]
    except UnicodeDecodeError as e:
        logging.error(f"Encoding error in the file: {e}")
        return [f"Encoding error: {e}"]
    return found_items

def calculate_hash(file_path, hash_algorithm='sha256'):
    """Calculates the hash of a file using the specified hash algorithm."""
    logging.info(f"Calculating hash for file at: {file_path} using {hash_algorithm}")
    if not os.path.exists(file_path):
        logging.error("File not found.")
        return None, "File not found."
    try:
        hash_obj = hashlib.new(hash_algorithm)
        with open(file_path, 'rb') as file:
            for chunk in iter(lambda: file.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest(), None
    except FileNotFoundError:
        logging.error("The file was not found.")
        return None, "File not found."
    except IOError as e:
        logging.error(f"An error occurred during file read: {e}")
        return None, f"An error occurred: {e}"

def analyze_pcap(file_path, display_filter=None):
    """Analyzes PCAP file to extract network packets based on a display filter."""
    try:
        capture = pyshark.FileCapture(file_path, display_filter=display_filter)
        packets = []
        for packet in capture:
            packets.append(packet)
        capture.close()
        return packets
    except Exception as e:
        logging.error(f"Failed to analyze pcap file: {e}")
        return None

def plot_packet_count(packets, title="Packet Count Over Time"):
    """Generates a plot of the number of packets over time."""
    if not packets:
        logging.error("No packets to plot.")
        return
    times = [float(packet.sniff_timestamp) for packet in packets if hasattr(packet, 'sniff_timestamp')]
    if not times:
        logging.error("No valid timestamps available for plotting.")
        return
    plt.figure(figsize=(10, 5))
    plt.plot(times, range(len(times)), marker='o')
    plt.title(title)
    plt.xlabel('Time (s)')
    plt.ylabel('Packet Count')
    plt.grid(True)
    plt.show()

def main():
    log_file_path = r"C:\Program Files\Microsoft OneDrive\setup\logs\Install-PerMachine_2024-04-04_061813_1740-5432.log"
    error_pattern = "error|failed|exception"
    log_analysis_results = analyze_logs(log_file_path, error_pattern)
    print("Log Analysis Results:")
    print(log_analysis_results)

    pcap_file_path = r"C:\Users\wells\OneDrive\Desktop\CYB333 Labs\PCAP.pcap"
    expected_hash = "4df94f5a090d7b8bba17f574ad953b9596ef98b50801a54d9fddebd2c4a2d1dd"
    hash_value, error = calculate_hash(pcap_file_path)
    if error:
        logging.error("Error calculating hash: " + error)
    elif hash_value != expected_hash:
        logging.error("File integrity check failed.")
        print(f"File hash {hash_value} does not match expected hash {expected_hash}.")
    else:
        print("File integrity check passed.")
        packets = analyze_pcap(pcap_file_path)
        if packets:
            plot_packet_count(packets)

if __name__ == "__main__":
    main()
