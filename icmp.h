#ifndef ICMP_UTIL_H
#define ICMP_UTIL_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <chrono>
#include <string>
#include <vector>
#include <netdb.h>
#include <sys/select.h>
#include <cerrno>
#include <iostream>
#include <thread>
#include <csignal>
#include <fstream>

namespace icmp_util {

    // Global flag for signal handling
    volatile sig_atomic_t interrupted = 0;

    // Log file for errors
    static std::ofstream log_file("dns_errors.log", std::ios::app);

    // Compute checksum for ICMP packet
    static uint16_t compute_checksum(const void* data, size_t len) {
        const uint16_t* buf = static_cast<const uint16_t*>(data);
        uint32_t sum = 0;
        while (len > 1) {
            sum += *buf++;
            len -= 2;
        }
        if (len == 1) {
            sum += *reinterpret_cast<const uint8_t*>(buf);
        }
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~static_cast<uint16_t>(sum);
    }

    // Result of a ping operation
    struct ping_result {
        bool success;
        std::chrono::milliseconds rtt;
    };

    // Send an ICMP Echo Request and wait for Echo Reply
    inline ping_result ping(const std::string& host, std::chrono::milliseconds timeout = std::chrono::milliseconds(250)) {
        // Resolve host to IPv4 address
        struct addrinfo hints = {};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_RAW;
        hints.ai_protocol = IPPROTO_ICMP;
        struct addrinfo* res;
        if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0) {
            log_file << "getaddrinfo failed for " << host << ": " << gai_strerror(errno) << "\n";
            return {false, std::chrono::milliseconds(0)};
        }
        struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
        std::string dest_ip = inet_ntoa(addr->sin_addr);

        // Create raw ICMP socket
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) {
            log_file << "socket creation failed for " << host << ": " << strerror(errno) << "\n";
            freeaddrinfo(res);
            return {false, std::chrono::milliseconds(0)};
        }

        // Construct ICMP Echo Request packet
        const size_t DATA_SIZE = 56;
        const size_t ICMP_HEADER_SIZE = sizeof(struct icmphdr);
        const size_t PACKET_SIZE = ICMP_HEADER_SIZE + DATA_SIZE;
        std::vector<char> packet(PACKET_SIZE);
        struct icmphdr* icmp = reinterpret_cast<struct icmphdr*>(packet.data());
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = htons(getpid() ^ std::hash<std::thread::id>{}(std::this_thread::get_id()));
        icmp->un.echo.sequence = htons(1);
        icmp->checksum = 0;
        std::memset(packet.data() + ICMP_HEADER_SIZE, 0, DATA_SIZE);
        icmp->checksum = compute_checksum(packet.data(), PACKET_SIZE);

        // Send packet
        struct sockaddr_in dest_addr = *addr;
        auto send_time = std::chrono::high_resolution_clock::now();
        if (sendto(sock, packet.data(), PACKET_SIZE, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
            log_file << "sendto failed for " << host << ": " << strerror(errno) << "\n";
            close(sock);
            freeaddrinfo(res);
            return {false, std::chrono::milliseconds(0)};
        }

        // Wait for Echo Reply
        auto end_time = send_time + timeout;
        while (std::chrono::high_resolution_clock::now() < end_time && !interrupted) {
            auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(end_time - std::chrono::high_resolution_clock::now());
            if (remaining <= std::chrono::microseconds(0)) {
                break;
            }

            struct timeval tv;
            tv.tv_sec = remaining.count() / 1000000;
            tv.tv_usec = remaining.count() % 1000000;

            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(sock, &readfds);

            int sel = select(sock + 1, &readfds, nullptr, nullptr, &tv);
            if (sel > 0) {
                std::vector<char> recv_buf(1500);
                struct sockaddr_in from_addr;
                socklen_t from_len = sizeof(from_addr);
                auto recv_time = std::chrono::high_resolution_clock::now();
                ssize_t received = recvfrom(sock, recv_buf.data(), recv_buf.size(), 0,
                                          (struct sockaddr*)&from_addr, &from_len);
                if (received < 0) {
                    log_file << "recvfrom failed for " << host << ": " << strerror(errno) << "\n";
                    close(sock);
                    freeaddrinfo(res);
                    return {false, std::chrono::milliseconds(0)};
                }
                if (received >= static_cast<ssize_t>(sizeof(struct iphdr) + sizeof(struct icmphdr))) {
                    struct iphdr* ip = reinterpret_cast<struct iphdr*>(recv_buf.data());
                    if (ip->protocol == IPPROTO_ICMP) {
                        size_t ip_hdr_len = ip->ihl * 4;
                        if (received >= static_cast<ssize_t>(ip_hdr_len + sizeof(struct icmphdr))) {
                            struct icmphdr* icmp_reply = reinterpret_cast<struct icmphdr*>(recv_buf.data() + ip_hdr_len);
                            std::string src_ip = inet_ntoa(from_addr.sin_addr);
                            if (icmp_reply->type == ICMP_ECHOREPLY &&
                                icmp_reply->un.echo.id == htons(getpid() ^ std::hash<std::thread::id>{}(std::this_thread::get_id())) &&
                                icmp_reply->un.echo.sequence == htons(1)) {
                                auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    recv_time - send_time);
                                if (src_ip != dest_ip) {
                                    log_file << "ICMP reply from wrong source for " << host << ": got " << src_ip << ", expected " << dest_ip << "\n";
                                }
                                close(sock);
                                freeaddrinfo(res);
                                return {true, rtt};
                            }
                        }
                    }
                }
            } else if (sel < 0) {
                log_file << "select failed for " << host << ": " << strerror(errno) << "\n";
                break;
            }
        }

        close(sock);
        freeaddrinfo(res);
        return {false, std::chrono::milliseconds(0)};
    }

} // namespace icmp_util

#endif // ICMP_UTIL_H