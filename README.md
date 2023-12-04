<b>AlertNet: Intrusion Detection System</b>

Overview

AlertNet is a Python-based Intrusion Detection System (IDS) designed to monitor network traffic and identify suspicious activities. It uses Scapy for packet sniffing and analysis, providing insights into SSH, HTTP, and DNS traffic. Developed with simplicity and educational purposes in mind, AlertNet serves as a basic yet functional tool for anyone interested in network security and Python scripting.

Features

SSH Monitoring: Detects potential brute-force attacks by tracking consecutive SSH login attempts.
HTTP Traffic Analysis: Logs basic metadata of HTTP traffic including source/destination IPs and ports, packet size, and TCP flags.


DNS Query Logging: Monitors DNS queries and logs the queried domain names.


Concurrent Processing: Utilizes threading to process packets concurrently while continuing to capture new packets.
Installation


Prerequisites


Python 3.x


Scapy


Any additional Python libraries (if used)


Setup


Clone the repository:



Copy code
git clone https://github.com/havasgaard/AlertNet.git


Install dependencies:

Copy code
pip install -r requirements.txt

Run the script:


Copy code
python alertnet.py


Usage
Run the script to start monitoring network traffic. The script needs to be run with sufficient privileges to capture network packets.

Copy code
sudo python alertnet.py


Contributing
Contributions to AlertNet are welcome! If you have suggestions or improvements, feel free to fork the repository and submit a pull request.

License
This project is licensed under the MIT License.

Acknowledgements
Scapy: For providing the packet manipulation capabilities.
Community Contributors: For improvements and bug fixes.
