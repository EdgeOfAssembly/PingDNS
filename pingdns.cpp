#include <sys/capability.h>
#include "icmp.h"
#include "progress_bar.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <string>
#include <numeric>
#include <regex>
#include <curl/curl.h>
#include <csignal>
#include <thread>
#include <atomic>
#include <climits>
#include <GeoIP.h>
#include <GeoIPCity.h>
#include <cstdlib>
#include <sys/stat.h>
#include <iomanip>
#include <unordered_set>

struct dns_server {
    std::string name;
    std::string ip;
    std::chrono::milliseconds avg_rtt;
    std::chrono::milliseconds min_rtt;
    std::chrono::milliseconds max_rtt;
    bool success;
    std::string country;
    std::string city;
};

// Global progress counter
std::atomic<size_t> progress{0};

void signal_handler(int sig) {
    icmp_util::interrupted = 1;
}

bool is_ipv4(const std::string& ip) {
    static const std::regex ipv4_regex(R"(^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$)");
    std::smatch match;
    if (!std::regex_match(ip, match, ipv4_regex)) {
        return false;
    }
    for (int i = 1; i <= 4; ++i) {
        int octet = std::stoi(match[i]);
        if (octet < 0 || octet > 255) {
            return false;
        }
    }
    return true;
}

size_t write_data(void* ptr, size_t size, size_t nmemb, void* stream) {
    return fwrite(ptr, size, nmemb, static_cast<FILE*>(stream));
}

time_t get_file_mtime(const std::string& filename) {
    struct stat st;
    if (stat(filename.c_str(), &st) == 0) {
        return st.st_mtime;
    }
    return 0;
}

bool download_file(const std::string& url, const std::string& outfile) {
    std::string temp_file = "temp_" + outfile;
    time_t mtime = get_file_mtime(outfile);
    CURLcode res = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (res != CURLE_OK) {
        std::cerr << "curl_global_init failed: " << curl_easy_strerror(res) << "\n";
        return false;
    }

    CURL* handle = curl_easy_init();
    if (!handle) {
        std::cerr << "curl_easy_init failed\n";
        curl_global_cleanup();
        return false;
    }

    FILE* fp = fopen(temp_file.c_str(), "wb");
    if (!fp) {
        std::cerr << "Failed to open temporary file: " << temp_file << "\n";
        curl_easy_cleanup(handle);
        curl_global_cleanup();
        return false;
    }

    curl_easy_setopt(handle, CURLOPT_URL, url.c_str());
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L);

    if (mtime > 0) {
        curl_easy_setopt(handle, CURLOPT_TIMEVALUE, static_cast<long>(mtime));
        curl_easy_setopt(handle, CURLOPT_TIMECONDITION, CURL_TIMECOND_IFMODSINCE);
    }

    res = curl_easy_perform(handle);
    long response_code = 0;
    curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &response_code);
    fclose(fp);

    if (res == CURLE_OK) {
        if (response_code == 200) {
            if (std::rename(temp_file.c_str(), outfile.c_str()) != 0) {
                std::cerr << "Failed to rename " << temp_file << " to " << outfile << "\n";
                std::remove(temp_file.c_str());
                curl_easy_cleanup(handle);
                curl_global_cleanup();
                return false;
            }
            std::cout << "Downloaded " << outfile << "\n";
            curl_easy_cleanup(handle);
            curl_global_cleanup();
            return true;
        } else if (response_code == 304) {
            std::remove(temp_file.c_str());
            std::cout << outfile << " is up-to-date\n";
            curl_easy_cleanup(handle);
            curl_global_cleanup();
            return false;
        } else {
            std::cerr << "Failed to download " << outfile << ": Unexpected response code " << response_code << "\n";
            std::remove(temp_file.c_str());
            curl_easy_cleanup(handle);
            curl_global_cleanup();
            return false;
        }
    } else {
        std::cerr << "Failed to download " << outfile << ": " << curl_easy_strerror(res) << "\n";
        std::remove(temp_file.c_str());
        curl_easy_cleanup(handle);
        curl_global_cleanup();
        return false;
    }
}

bool unzip_file(const std::string& infile, const std::string& outfile) {
    std::string cmd = "gzip -dc " + infile + " > " + outfile;
    int ret = system(cmd.c_str());
    if (ret != 0) {
        std::cerr << "Failed to unzip " << infile << "\n";
        return false;
    }
    return true;
}

// Modified ping_servers to accept configurable ping count and timeout
void ping_servers(std::vector<dns_server>& servers, size_t start, size_t end, size_t server_count, int ping_count, int timeout_ms) {
    for (size_t i = start; i < end && !icmp_util::interrupted; ++i) {
        auto& server = servers[i];
        std::vector<std::chrono::milliseconds> rtts;
        for (int j = 0; j < ping_count && !icmp_util::interrupted; ++j) {
            auto result = icmp_util::ping(server.ip, std::chrono::milliseconds(timeout_ms));
            if (result.success) {
                rtts.push_back(result.rtt);
            }
        }
        if (!rtts.empty()) {
            auto total_rtt = std::accumulate(rtts.begin(), rtts.end(), std::chrono::milliseconds(0));
            server.avg_rtt = total_rtt / rtts.size();
            server.min_rtt = *std::min_element(rtts.begin(), rtts.end());
            server.max_rtt = *std::max_element(rtts.begin(), rtts.end());
            server.success = true;
        } else {
            server.success = false;
        }
        progress_bar("Scanning DNS servers", ++progress, server_count);
    }
}

bool get_geolocation(const std::string& ip, std::string& country, std::string& city) {
    GeoIP* gi = GeoIP_open("GeoIPCity.dat", GEOIP_MEMORY_CACHE);
    if (!gi) {
        std::cerr << "Failed to open GeoIPCity.dat\n";
        return false;
    }

    GeoIPRecord* record = GeoIP_record_by_addr(gi, ip.c_str());
    bool found = false;
    if (record) {
        country = record->country_name ? record->country_name : "Unknown";
        city = record->city ? record->city : "";
        found = true;
        GeoIPRecord_delete(record);
    } else {
        country = "Unknown";
        city = "";
    }

    GeoIP_delete(gi);
    return found;
}

bool has_raw_socket_privileges() {
    if (geteuid() == 0) {
        return true;
    }
    cap_t caps = cap_get_proc();
    if (!caps) {
        std::cerr << "Error: Failed to get process capabilities\n";
        return false;
    }
    cap_flag_value_t cap_net_raw_state;
    if (cap_get_flag(caps, CAP_NET_RAW, CAP_EFFECTIVE, &cap_net_raw_state) == -1) {
        std::cerr << "Error: Failed to check CAP_NET_RAW capability\n";
        cap_free(caps);
        return false;
    }
    bool has_cap_net_raw = (cap_net_raw_state == CAP_SET);
    cap_free(caps);
    return has_cap_net_raw;
}

int main(int argc, char* argv[]) {
    std::signal(SIGINT, signal_handler);

    if (!has_raw_socket_privileges()) {
        std::cerr << "Error: This program requires raw socket privileges to perform ICMP pings.\n"
                  << "Please run the program with sudo:\n"
                  << "  sudo " << argv[0] << " [options]\n"
                  << "Alternatively, set the CAP_NET_RAW capability:\n"
                  << "  sudo setcap cap_net_raw+ep " << argv[0] << "\n"
                  << "Then run the program normally:\n"
                  << "  " << argv[0] << " [options]\n";
        return 1;
    }

    // Default values for configurable parameters
    size_t total_to_scan = SIZE_MAX;
    int ping_count = 3;          // Default: 3 pings per server
    int timeout_ms = 250;        // Default: 250ms timeout
    unsigned int num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 4;

    // Parse command-line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-n" && i + 1 < argc) {
            try {
                total_to_scan = std::stoul(argv[++i]);
            } catch (const std::exception& e) {
                std::cerr << "Error: Invalid number for -n: " << argv[i] << "\n";
                return 1;
            }
        } else if (arg == "-pings" && i + 1 < argc) {
            try {
                ping_count = std::stoi(argv[++i]);
                if (ping_count < 1) {
                    std::cerr << "Error: -pings must be at least 1\n";
                    return 1;
                }
            } catch (const std::exception& e) {
                std::cerr << "Error: Invalid value for -pings: " << argv[i] << "\n";
                return 1;
            }
        } else if (arg == "-timeout" && i + 1 < argc) {
            try {
                timeout_ms = std::stoi(argv[++i]);
                if (timeout_ms <= 0) {
                    std::cerr << "Error: -timeout must be positive\n";
                    return 1;
                }
            } catch (const std::exception& e) {
                std::cerr << "Error: Invalid value for -timeout: " << argv[i] << "\n";
                return 1;
            }
        } else if (arg == "-t" && i + 1 < argc) {
            try {
                num_threads = std::stoi(argv[++i]);
                if (num_threads < 1) {
                    std::cerr << "Error: -t must be at least 1\n";
                    return 1;
                }
            } catch (const std::exception& e) {
                std::cerr << "Error: Invalid value for -t: " << argv[i] << "\n";
                return 1;
            }
        } else {
            std::cerr << "Usage: " << argv[0] << " [-n <number>] [-pings <count>] [-timeout <ms>] [-t <threads>]\n";
            return 1;
        }
    }

    // Initialize with hardcoded DNS servers
    std::vector<dns_server> servers = {
        {"Google DNS", "8.8.8.8", {}, {}, {}, false, "", ""},
        {"Google DNS", "8.8.4.4", {}, {}, {}, false, "", ""},
        {"Cloudflare DNS", "1.1.1.1", {}, {}, {}, false, "", ""},
        {"Cloudflare DNS", "1.0.0.1", {}, {}, {}, false, "", ""},
        {"Quad9 DNS", "9.9.9.9", {}, {}, {}, false, "", ""},
        {"Quad9 DNS", "149.112.112.112", {}, {}, {}, false, "", ""},
        {"OpenDNS", "208.67.222.222", {}, {}, {}, false, "", ""},
        {"OpenDNS", "208.67.220.220", {}, {}, {}, false, "", ""},
        {"DNS.Watch", "84.200.69.80", {}, {}, {}, false, "", ""},
        {"DNS.Watch", "84.200.70.40", {}, {}, {}, false, "", ""},
        {"Level 3", "209.244.0.3", {}, {}, {}, false, "", ""},
        {"Level 3", "209.244.0.4", {}, {}, {}, false, "", ""},
        {"Control D", "76.76.2.0", {}, {}, {}, false, "", ""},
        {"Control D", "76.76.10.0", {}, {}, {}, false, "", ""},
        {"AdGuard DNS", "94.140.14.14", {}, {}, {}, false, "", ""},
        {"AdGuard DNS", "94.140.15.15", {}, {}, {}, false, "", ""},
        {"Verisign DNS", "64.6.64.6", {}, {}, {}, false, "", ""},
        {"Verisign DNS", "64.6.65.6", {}, {}, {}, false, "", ""},
        {"Elisa FI", "193.110.224.10", {}, {}, {}, false, "", ""},
        {"CleanBrowsing", "185.228.168.168", {}, {}, {}, false, "", ""},
        {"CleanBrowsing", "185.228.169.168", {}, {}, {}, false, "", ""}
    };

    // Ensure IP uniqueness
    std::unordered_set<std::string> ip_set;
    for (const auto& server : servers) {
        ip_set.insert(server.ip);
    }

    // **Enhancement 1: Download with better feedback**
  bool server_list_downloaded = download_file("https://public-dns.info/nameservers.txt", "nameservers.txt");
    std::ifstream server_check("nameservers.txt");
    if (server_list_downloaded) {
        std::cout << "Downloaded nameservers.txt\n";
    } else if (server_check.good()) {
        std::cout << "Using existing nameservers.txt\n";
    } else {
        std::cout << "No nameservers.txt available, using hardcoded servers only\n";
    }
    server_check.close();

    // **Handle GeoIPCity.dat**
    bool geoip_available = false;
    std::ifstream geoip_check("GeoIPCity.dat");
    if (geoip_check.good()) {
        std::cout << "Using existing GeoIPCity.dat for geolocation\n";
        geoip_available = true;
    } else {
        bool geoip_downloaded = download_file("https://mailfud.org/geoip-legacy/GeoIPCity.dat.gz", "GeoIPCity.dat.gz");
        if (geoip_downloaded) {
            if (unzip_file("GeoIPCity.dat.gz", "GeoIPCity.dat")) {
                std::cout << "Downloaded and extracted GeoIPCity.dat\n";
                geoip_available = true;
            } else {
                std::cerr << "Failed to extract GeoIPCity.dat, geolocation unavailable\n";
            }
        } else {
            std::ifstream gz_check("GeoIPCity.dat.gz");
            if (gz_check.good()) {
                if (unzip_file("GeoIPCity.dat.gz", "GeoIPCity.dat")) {
                    std::cout << "Extracted GeoIPCity.dat from existing archive\n";
                    geoip_available = true;
                } else {
                    std::cerr << "Failed to extract GeoIPCity.dat, geolocation unavailable\n";
                }
            } else {
                std::cerr << "No GeoIP data available, geolocation unavailable\n";
            }
            gz_check.close();
        }
    }
    geoip_check.close();

    // Load servers from nameservers.txt if it exists
    std::ifstream file("nameservers.txt");
    if (file.is_open()) {
        std::string ip;
        while (servers.size() < total_to_scan && std::getline(file, ip) && !icmp_util::interrupted) {
            ip.erase(std::remove_if(ip.begin(), ip.end(), isspace), ip.end());
            if (is_ipv4(ip) && ip_set.insert(ip).second) {
                servers.push_back({"Public DNS", ip, {}, {}, {}, false, "", ""});
            }
        }
        file.close();
    }









    // **Enhancement 2: Report number of servers to scan**
    size_t num_to_scan = (total_to_scan == SIZE_MAX) ? servers.size() : std::min(servers.size(), total_to_scan);
    size_t server_count = num_to_scan;
    std::cout << "Total DNS servers to scan: " << num_to_scan << "\n";

    // Launch pinging threads with configurable parameters
    std::vector<std::thread> threads;
    progress = 0;
    progress_bar("Scanning DNS servers", 0, server_count);
    size_t servers_per_thread = (server_count + num_threads - 1) / num_threads;
    for (unsigned int i = 0; i < num_threads && i * servers_per_thread < server_count; ++i) {
        size_t start = i * servers_per_thread;
        size_t end = std::min(start + servers_per_thread, server_count);
        threads.emplace_back(ping_servers, std::ref(servers), start, end, server_count, ping_count, timeout_ms);
    }

    // Wait for all threads to complete
    for (auto& t : threads) {
        t.join();
    }

    // Collect successful servers and add geolocation
    std::vector<dns_server> successful_servers;
    for (size_t i = 0; i < num_to_scan; ++i) {
        auto& server = servers[i];
        if (server.success) {
            std::string country, city;
            if (get_geolocation(server.ip, country, city)) {
                server.country = country;
                server.city = city;
            } else {
                server.country = "Unknown";
                server.city = "";
            }
            successful_servers.push_back(server);
        }
    }

    // Sort by average RTT
    if (!successful_servers.empty()) {
        std::sort(successful_servers.begin(), successful_servers.end(),
            [](const dns_server& a, const dns_server& b) { return a.avg_rtt < b.avg_rtt; });
    }

    // Write results to CSV with updated header
    std::ofstream csv("dns_results.csv");
    if (csv.is_open()) {
        csv << "Name,IP,Location,Avg RTT (ms)\n";
        for (const auto& server : successful_servers) {
            std::string location = server.country + (server.city.empty() ? "" : ", " + server.city);
            csv << "\"" << server.name << "\"," << server.ip << ","
                << "\"" << location << "\"," << server.avg_rtt.count() << "\n";
        }
        csv.close();
    } else {
        std::cerr << "Warning: Could not open dns_results.csv\n";
    }

    // **Enhancement 3: Handle no successful servers**
    if (!icmp_util::interrupted) {
        if (!successful_servers.empty()) {
            std::cout << "\n\nDNS Servers Sorted by Average Latency (Fastest to Slowest):\n";
            std::cout << "----------------------------------------------------------------------------\n";
            for (const auto& server : successful_servers) {
                std::string location = server.country + (server.city.empty() ? "" : ", " + server.city);
                std::string latency = std::to_string(server.avg_rtt.count()) + " ms";
                std::cout << std::left << std::setw(20) << server.name
                          << std::left << std::setw(16) << server.ip
                          << std::left << std::setw(30) << location
                          << std::left << std::setw(10) << latency << "\n";
            }
        } else {
            std::cout << "\nNo DNS servers responded successfully.\n";
        }
    }

    return 0;
}

