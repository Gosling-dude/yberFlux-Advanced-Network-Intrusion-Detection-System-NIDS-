#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <map>
#include <chrono>

// --- Configuration ---
const int SSH_ATTEMPT_THRESHOLD = 6;      // Block after 6 failed attempts
const int SSH_TIME_WINDOW_SECONDS = 240;  // within a 4-minute window (240s)

// --- Data Structures ---

// To track SSH login attempts
struct SshTracker {
    int attempt_count;
    std::chrono::system_clock::time_point first_attempt_time;
    bool alerted; // To prevent sending multiple alerts for the same IP
};

// To store known IP-MAC address mappings
std::map<std::string, std::string> ip_mac_map;

// To track SSH attempts from various IPs
std::map<std::string, SshTracker> ssh_attack_candidates;


// --- Helper function to split a string by a delimiter ---
std::vector<std::string> split(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        // Trim leading/trailing whitespace from the token
        size_t first = token.find_first_not_of(" \t\n\r");
        if (std::string::npos == first) {
            tokens.push_back("");
            continue;
        }
        size_t last = token.find_last_not_of(" \t\n\r");
        tokens.push_back(token.substr(first, (last - first + 1)));
    }
    return tokens;
}

// --- Main analysis function ---
void analyze_log_line(const std::string& line) {
    std::vector<std::string> parts = split(line, '|');
    if (parts.size() < 4) {
        return; // Malformed or comment line, ignore
    }

    std::string timestamp_str = parts[0];
    std::string type = parts[1];
    std::string src_ip = parts[2];

    // 1. ARP Spoofing Detection Logic
    if (type == "ARP") {
        std::string claimed_ip = parts[2];
        std::string new_mac = parts[4];

        if (ip_mac_map.count(claimed_ip)) {
            // IP is already known. Check if the MAC has changed.
            if (ip_mac_map[claimed_ip] != new_mac && !new_mac.empty()) {
                std::cout << "ALERT | ARP_SPOOFING | " << claimed_ip << " | New MAC: " << new_mac << " | Original MAC: " << ip_mac_map[claimed_ip] << std::endl;
            }
        } else {
            // First time seeing this IP, store it.
            ip_mac_map[claimed_ip] = new_mac;
        }
    }

    // 2. SSH Brute-Force Detection Logic
    else if (type == "SSH" && parts.size() >= 5 && parts[4].find("status:FAIL") != std::string::npos) {
        auto& tracker = ssh_attack_candidates[src_ip]; // Get or create tracker for this IP

        if (tracker.alerted) {
             return; // We have already flagged this IP, do nothing.
        }

        auto now = std::chrono::system_clock::now();

        // Check if the previous attempts are outside the time window
        if (tracker.attempt_count > 0) {
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - tracker.first_attempt_time).count();
            if (duration > SSH_TIME_WINDOW_SECONDS) {
                // Reset the counter if the last attempt was too long ago
                tracker.attempt_count = 1;
                tracker.first_attempt_time = now;
            } else {
                tracker.attempt_count++;
            }
        } else {
            // This is the first recorded attempt
            tracker.attempt_count = 1;
            tracker.first_attempt_time = now;
        }

        // Check if the threshold has been reached
        if (tracker.attempt_count >= SSH_ATTEMPT_THRESHOLD) {
            std::cout << "ALERT | SSH_BRUTE_FORCE | " << src_ip << " | Attempts: " << tracker.attempt_count << std::endl;
            tracker.alerted = true; // Mark as alerted
        }
    }
}


int main() {
    std::string line;
    // Read from standard input (cin) line by line
    while (std::getline(std::cin, line)) {
        if (line.rfind("#", 0) == 0 || line.empty()) {
            continue; // Ignore comment lines and empty lines
        }
        analyze_log_line(line);
    }
    return 0;
}