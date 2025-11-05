#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <map>
#include <chrono>

using namespace std;

// --- Configuration ---
const int SSH_ATTEMPT_THRESHOLD = 6;
const int SSH_TIME_WINDOW_SECONDS = 240;

// --- Data Structures ---
struct SshTracker {
    int attempt_count;
    chrono::system_clock::time_point first_attempt_time;
    bool alerted;
};

map<string, string> ip_mac_map;
map<string, SshTracker> ssh_attack_candidates;

// --- Helper function to split a string by a delimiter ---
vector<string> split(const string& s, char delimiter) {
    vector<string> tokens;
    string token;
    istringstream tokenStream(s);
    while (getline(tokenStream, token, delimiter)) {
        size_t first = token.find_first_not_of(" \t\n\r");
        if (string::npos == first) {
            tokens.push_back("");
            continue;
        }
        size_t last = token.find_last_not_of(" \t\n\r");
        tokens.push_back(token.substr(first, (last - first + 1)));
    }
    return tokens;
}

// --- Main analysis function ---
void analyze_log_line(const string& line) {
    vector<string> parts = split(line, '|');
    if (parts.size() < 4) return;

    string timestamp_str = parts[0];
    string type = parts[1];
    string src_ip = parts[2];

    if (type == "ARP") {
        string claimed_ip = parts[2];
        string new_mac = parts[4];

        if (ip_mac_map.count(claimed_ip)) {
            if (ip_mac_map[claimed_ip] != new_mac && !new_mac.empty()) {
                cout << "ALERT | ARP_SPOOFING | " << claimed_ip << " | New MAC: " 
                     << new_mac << " | Original MAC: " << ip_mac_map[claimed_ip] << endl;
            }
        } else {
            ip_mac_map[claimed_ip] = new_mac;
        }
    }

    else if (type == "SSH" && parts.size() >= 5 && parts[4].find("status:FAIL") != string::npos) {
        auto& tracker = ssh_attack_candidates[src_ip];

        if (tracker.alerted) return;

        auto now = chrono::system_clock::now();

        if (tracker.attempt_count > 0) {
            auto duration = chrono::duration_cast<chrono::seconds>(now - tracker.first_attempt_time).count();
            if (duration > SSH_TIME_WINDOW_SECONDS) {
                tracker.attempt_count = 1;
                tracker.first_attempt_time = now;
            } else tracker.attempt_count++;
        } else {
            tracker.attempt_count = 1;
            tracker.first_attempt_time = now;
        }

        if (tracker.attempt_count >= SSH_ATTEMPT_THRESHOLD) {
            cout << "ALERT | SSH_BRUTE_FORCE | " << src_ip 
                 << " | Attempts: " << tracker.attempt_count << endl;
            tracker.alerted = true;
        }
    }
}

int main() {
    string line;
    while (getline(cin, line)) {
        if (line.rfind("#", 0) == 0 || line.empty()) continue;
        analyze_log_line(line);
    }
    return 0;
}
