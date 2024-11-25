#GhostEnum

GhostEnum is a stealthy network enumeration and port scanning toolkit designed for red teams and penetration testers. It automates host discovery, port scanning, and provides actionable results with flexibility and stealth techniques. Ideal for post-exploitation reconnaissance, GhostEnum helps gather insights into target networks while maintaining operational stealth.
Key Features

    Stealthy Network Scanning:
        ICMP-based host discovery to identify live systems in the network.
        TCP SYN and UDP port scanning with randomized port order and delays to evade detection.
    Customizable Port Ranges:
        Scan specific or full port ranges as required for the engagement.
    Actionable Results:
        Organized outputs with open ports and host details saved to a file for further analysis.
    User-Friendly Command-Line Interface:
        Easy-to-use CLI with options for target network, port ranges, and output file customization.

#Use Cases

    Red Teaming:
    Conduct stealthy enumeration during engagements without alerting monitoring systems.
    Penetration Testing:
    Identify open ports and active hosts to discover potential attack vectors.
    Post-Exploitation:
    Enumerate internal networks after gaining a foothold in a system.

#How It Works

    Host Discovery:
    Uses ICMP requests to identify live hosts within a specified network.
    Port Scanning:
        TCP SYN Scan quickly identifies open TCP ports.
        UDP Scan detects services running over UDP, with handling for filtered and closed responses.
    Stealth Techniques:
        Randomized scanning order and delays between packets to avoid detection.
        Configurable port ranges and scan intensity.
    Output Management:
    Saves results to a specified file for later use.

#Installation

    Clone the repository by running:
    `git clone git@github.com:un1xr00t/GhostEnum.git`
    Then navigate to the project folder with:
    `cd GhostEnum`

    Install dependencies by running:
    `pip install -r requirements.txt`
    Note that GhostEnum uses Python and the scapy library.

Usage

Run GhostEnum with the following options:

python ghostenum.py -n <network> [-p <ports>] [-o <output>]
Options:

    -n or --network: Specifies the target network or host, such as 192.168.1.0/24 or 192.168.1.100. (Required)
    -p or --ports: Specifies the port range to scan, with a default of 1-1024.
    -o or --output: Specifies the output file for saving results, with a default of scan_results.txt.

Examples:

    To scan an entire network:
    `python ghostenum.py -n 192.168.1.0/24`

    To scan a single host for specific ports:
    `python ghostenum.py -n 192.168.1.100 -p 20-80`

    To save results to a custom file:
    `python ghostenum.py -n 192.168.1.0/24 -o results.txt`

Planned Features

    Exploitation Module:
    Automate the detection and exploitation of known vulnerabilities in services.
    Pivoting Support:
    Use `SOCKS` proxies to route traffic through compromised systems.
    Visualization:
    Graphical representation of network topologies and open ports.

Contributing

Contributions are welcome. If you would like to add features, fix bugs, or improve documentation:

    Fork the repository.
    Create a new branch with a name such as feature/your-feature-name.
    Commit your changes and push them to GitHub.
    Open a pull request.

License

This project is licensed under the MIT License. See the LICENSE file for details.

This version includes inline backticks for commands and file names, making it clean and professional. Let me know if there’s anything else you’d like to tweak!
