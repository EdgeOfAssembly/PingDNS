# PingDNS

PingDNS is a command-line tool for mass pinging DNS servers to measure their latency using ICMP pings. It supports scanning up to 60,000 servers efficiently with multi-threading, configurable ping parameters, and optional geolocation data retrieval via GeoIP.

## Features
- Mass ping DNS servers (hardcoded and from public-dns.info)
- Multi-threaded for high performance
- Configurable ping count, timeout, and thread count
- Geolocation support for server location data
- Outputs results to console and `dns_results.csv`

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/EdgeOfAssembly/PingDNS.git

2. Navigate to the directory:
   cd PingDNS

3. Build with CMake:
   mkdir build && cd build
   cmake ..
   make

4. Run the tool (requires raw socket privileges):
   sudo ./pingdns [options]

Note: Use sudo or set CAP_NET_RAW capability:
   sudo setcap cap_net_raw+ep pingdns


## Usage
1. Basic scan:
   sudo ./pingdns

2. Scan 100 servers with 5 pings each, 500ms timeout, and 8 threads:
   sudo ./pingdns -n 100 -pings 5 -timeout 500 -t 8

See the man page (docs/pingdns.1) for more examples.

## Dependencies
   libcurl
   libGeoIP
   libcap

1. Install on Ubuntu:
   sudo apt-get install libcurl4-openssl-dev libgeoip-dev libcap-dev


## License
This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.
