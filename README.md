# Rmap (Resolution mapping)

Rmap is a tool designed for probing the full-resolution topology of domains. It assists security researchers and network engineers in analyzing domain configurations and identifying potential issues. Rmap enables the probing and discovery of all dependencies and configuration information associated with a domain, as it can initiate probing from the root domain servers to retrieve all dependency-related information of the target domain. This includes the configurations of various types of resource records, such as nameserver records, A records, AAAA records, NS records, and CNAME records. Additionally, based on Rmap, you can discover the dependency relationships between different authoritative domain name servers, thereby identifying various possible potential security issues.

## Features

Rmap provides multiple operation modes, supporting single-domain or batch-domain analysis:

| Mode (`-mod`) | Description |
|----------------|------------|
| 1 | Todo functionality |
| 2 | Generate JSON output file. Located in pkg/visual/store/ |
| 3 | Identify DNS misconfigurations |
| 4 | All corresponding IP addresses |
| 5 | All nameservers |
| 6 | All AAAA (IPv6) records |
| 7 | The full-resolution topology |
| 8 | All IPv6 nameservers |
| 9 | Detect DNS resolution cycles |


## Prerequisites
Ensure you have Go 1.21 or higher installed (for module support and compatibility with dependencies). You can check your Go version with:

```bash
go version
```

The server must support both IPv4 and IPv6 protocols simultaneously.

## Installation

Make sure you have Go installed (>= 1.21):

```bash
git clone https://github.com/ahlien/rmap.git
cd rmap
go build -o rmap main.go
```



## Required Flags

At least one of the following flags must be provided to specify the target domain(s):

- `-d <domain>`: Single domain input (e.g., example.com).
- `-l <domain-list-file>`: Path to a file containing a list of domains (one domain per line).

Additionally, the `-mod` flag is mandatory to specify the operation mode (value range: 1–9).

## Optional Flags

| Flag | Description | Default Value |
|------|-------------|---------------|
| `-p <pool-size>` | Worker pool size for batch domain processing (must be a positive integer). | Automatically set: 1 for single domain (`-d`), 100 for domain list (`-l`). |
| `-output <file-path>` | Path for the output CSV file (stores analysis results). | Automatically set: `domain.csv` for single domain (`-d`), `<domain-list-file-name>.csv` for domain list (`-l`). |
| `-v <ip-version>` | IP version to use for DNS queries:<br>4 = IPv4 only, 6 = IPv6 only, 0 = Dual-stack (IPv4 + IPv6). | 0 (dual-stack) |
| `-proto <protocol>` | Network protocol for DNS queries:<br>tcp (for large responses, e.g., long record lists), udp (faster for most cases). | udp |

## Usage Examples

### Analyze a Single Domain (Retrieve NS Records)

Retrieve NS records for `example.com` using dual-stack IP and UDP protocol, with default output:

```bash
./rmap -d example.com -mod 5
```


### Batch Analyze Domains (Detect DNS Cycles)

Process a domain list (`domains.txt`), use a worker pool size of 50:

```bash
./rmap -l ./domains.txt -mod 9 -p 50
```

### Probe Network Topology (IPv6 Only, TCP Protocol)

Probe the network topology of `test.com` using only IPv6 and TCP for DNS queries:

```bash
./rmap -d test.com -mod 7 -v 6 -proto tcp
```


### Generate JSON Output for a Domain List

Generate JSON output (via -mod 2) for domains in my-domains.txt, with a worker pool size of 30:
```bash
./rmap -l ./my-domains.txt -mod 2 -p 30
```

### Notes

- **Worker Pool Size**: For large domain lists, adjust `-p` based on your network bandwidth and system resources (larger values speed up processing but increase resource usage).  
- **Protocol Selection**: Use `-proto tcp` if you encounter truncated DNS responses (common with large record sets, e.g., multiple AAAA records).  
- **IP Version Compatibility**: Ensure your network environment supports IPv6.  
- **Output Files**: The CSV file contains various potential misconfigurations of domain names, whereas the JSON outputs (-mod 2) provide comprehensive information on all dependencies of the domains, including node details, inter-node dependencies, and the complete resolution topology of the domains.


If you want to quickly experiment with all the parameters of Rmap, you can run the **run.sh** script. Moreover, since we probe the complete resolution topology of domains by interacting directly with the nameservers, you can modify Rmap to collect any information related to domain resolution as needed.

```bash
#!/bin/bash

# -d single domain test
DOMAIN="baidu.com"
PROTOCOL_UDP="udp"

echo "=== Running single domain: $DOMAIN with protocol $PROTOCOL_UDP ==="
for VERSION in 0,4,6 ; do
    echo ">>> Testing IP version: $VERSION"
    for MOD in {2..10}; do
        echo "Running mod=$MOD ..."
        go run main.go -d "$DOMAIN" -mod "$MOD" -proto "$PROTOCOL_UDP" -v "$VERSION"
        echo "Finished mod=$MOD"
        echo "-----------------------------"
    done
done

# -d domain list test
DOMAIN_LIST_FILE="domainlist.txt"
PROTOCOL_TCP="tcp"

echo "=== Running domain list: $DOMAIN_LIST_FILE with protocol $PROTOCOL_TCP ==="
for VERSION in 0 4 6; do
    echo ">>> Testing IP version: $VERSION"
    for MOD in {2..10}; do
        echo "Running mod=$MOD ..."
        go run main.go -l "$DOMAIN_LIST_FILE" -mod "$MOD" -proto "$PROTOCOL_TCP" -v "$VERSION"
        echo "Finished mod=$MOD"
        echo "-----------------------------"
    done
done

echo "All tasks finished."
```

## Paper

- **\[IMC Poster '25\]** **Fasheng Miao**, Shuying Zhuang, Xiang Li, Changqing An, Deliang Chang, Baojun Liu, Jia Zhang and Jilong Wang. **RMap: Uncovering Risky DNS Resolution Chains and Misconfigurations**. In Proceedings of ACM Internet Measurement Conference 2025 (IMC '25). Madison, Wisconsin, USA.
