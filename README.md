# NetworkShark: Advanced PCAP Data Analyzer

## Project Description
The NetworkShark: Advanced PCAP Data Analyzer is a Python-based tool designed to automate the extraction and analysis of data from pcap files, which are extensively used for capturing network packet data. This tool simplifies the process of filtering and visualizing network traffic, making it invaluable for cybersecurity analysts, network administrators, and students engaged in network analysis and security studies.

The software aims to improve efficiency in handling large volumes of network data and reduce human error in data analysis. By providing functionalities such as advanced data filtering and basic visualization, NetworkShark enables users to quickly identify and respond to potential network anomalies and security threats.

### Target Audience
Cybersecurity Professionals: For those tasked with monitoring and analyzing network traffic to detect security threats.

Network Administrators: To assist in managing and troubleshooting network operations by providing insights into traffic patterns.

Academic Researchers and Students: Particularly useful for those in network security and forensic analysis courses, helping them learn about real-world data traffic analysis.

IT Consultants: Professionals who require a tool to analyze network data efficiently for their consultancy in network setup and security assessments.

This project enhances learning and professional development in network-related disciplines and contributes to more secure and efficient network management practices.

#### Features
- **Log Analysis**: Analyze log files for specific patterns and errors using regular expressions. Supports customizable encoding settings.
- **File Integrity Check**: Calculate file hashes to verify the integrity of data, with support for multiple hashing algorithms including SHA256.
- **PCAP Analysis**: Load and analyze PCAP files to extract network packets, with options to apply display filters.
- **Data Visualization**: Generate visual plots of packet counts over time to help in understanding network traffic patterns.
- **Error Handling**: Robust logging and error handling to provide clear diagnostics and operational status.


##### Installation
To install NetworkShark, clone this repository and install the required Python packages:

git clone https://github.com/Wellsworthb/NetworkShark-Advanced-PCAP-Data-Analyzer-.git
cd NetworkShark
pip install -r requirements.txt

###### Usage
To run NetworkShark, navigate to the directory containing NetworkShark.py and execute the script:

e.g python NetworkShark.py --file C:\Users\wells\OneDrive\Desktop\CYB333 Labs\PCAP.pcap

####### Usage Example
Example code demonstrating how to use NetworkShark
from NetworkShark import PCAPAnalyzer

# Initialize PCAPAnalyzer
analyzer = PCAPAnalyzer()
# Load PCAP file
analyzer.load_pcap("example.pcap")
# Perform analysis
results = analyzer.analyze()
# Display results
print(results)

####### Contributing
Contributions to NetworkShark are welcome! Please fork the repository, make your changes, and submit a pull request.

######## License
NetworkShark is released under the MIT License. See the LICENSE file for more details.

##### Contact
For any queries or technical support, please contact Your wellsbethelmie@gmail.com.

######### Acknowledgements
Thanks to everyone who has contributed to the development of NetworkShark.
