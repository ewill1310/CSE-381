/**Copyright 2023 Evan Williams
 * A program to detect potential attempts at trying to break into
 * accounts by scanning logs on a Linux machine. Breakin attempts are
 * detected using the two rules listed further below.
 *
 *   1. If an IP is in the "banned list", then it is flagged as a
 *      break in attempt.
 *
 *   2. unless an user is in the "authorized list", if an user has
 *      attempted to login more than 3 times in a span of 20 seconds
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <boost/asio.hpp>

// Convenience namespace declarations to streamline the code below
using namespace boost::asio;
using namespace boost::asio::ip;
using namespace std;

/** Synonym for an unordered map that is used to track banned IPs and 
 * authorized users. For example, the key in this map would be IP addresses
 * and the value is just a place holder (is always set to true).
 */
using LookupMap = std::unordered_map<std::string, bool>;

/**
 * An unordered map to track the seconds for each log entry associated
 * with each user. The user ID is the key into this unordered map.
 * The values is a list of timestamps of log entries associated with
 * an user. For example, if a user "bob" has 3 login at "Aug 29 11:01:01",
 * "Aug 29 11:01:02", and "Aug 29 11:01:03" (one second apart each), then
 * logins["bill"] will be a vector with values {1630249261, 1630249262, 
 * 1630249263}. 
 */
using LoginTimes = std::unordered_map<std::string, std::vector<long>>;

/**
 * Helper method to load data from a given file into an unordered map.
 * 
 * @param fileName The file name from words are are to be read by this 
 * method. The parameter value is typically "authorized_users.txt" or
 * "banned_ips.txt".
 * 
 * @return Return an unordered map with the 
 */
LookupMap loadLookup(const std::string& fileName) {
    // Open the file and check to ensure that the stream is valid
    std::ifstream is(fileName);
    if (!is.good()) {
        throw std::runtime_error("Error opening file " + fileName);
    }
    // The look up map to be populated by this method.
    LookupMap lookup;
    // Load the entries into the unordered map
    for (std::string entry; is >> entry;) {
        lookup[entry] = true;
    }
    // Return the loaded unordered map back to the caller.
    return lookup;
}

/**
 * This method is used to convert a timestamp of the form "Jun 10
 * 03:32:36" to seconds since Epoch (i.e., 1970-01-01 00:00:00). This
 * method assumes by default, the year is 2021.
 *
 * \param[in] timestamp The timestamp to be converted to seconds.  The
 * timestamp must be in the format "Month day Hour:Minutes:Seconds",
 * e.g. "Jun 10 03:32:36".
 *
 * \param[in] year An optional year associated with the date. By
 * default this value is assumed to be 2021.
 *
 * \return This method returns the seconds elapsed since Epoch.
 */
long toSeconds(const std::string& timestamp, const int year = 2021) {
    // Initialize the time structure with specified year.
    struct tm tstamp = { .tm_year = year - 1900 };
    // Now parse out the values from the supplied timestamp
    strptime(timestamp.c_str(), "%B %d %H:%M:%S", &tstamp);
    // Use helper method to return seconds since Epoch
    return mktime(&tstamp);
}

/**
 * Helper method to setup a TCP stream for downloading data from an
 * web-server.
 * 
 * @param host The host name of the web-server. Host names can be of
 * the from "www.miamioh.edu" or "ceclnx01.cec.miamioh.edu".  This
 * information is typically extracted from a given URL.
 *
 * @param path The path to the file being download.  An example of
 * this value is ""
 *
 * @param socket The TCP stream (aka socket) to be setup by this
 * method.  After a successful call to this method, this stream will
 * contain the response from the web-server to be processed.
 *
 * @param port An optional port number. The default port number is "80"
 *
 */
void setupDownload(const std::string& hostName, const std::string& path,
                   tcp::iostream& data, const std::string& port = "80") {
    // Create a boost socket and request the log file from the server.
    data.connect(hostName, port);
    data << "GET "   << path     << " HTTP/1.1\r\n"
         << "Host: " << hostName << "\r\n"
         << "Connection: Close\r\n\r\n";
}

/**
 * Helper method to detect hacking due to a login time violation.
 * Specifically if there are over 3 login attempts by a single 
 * user ID within a 20 second period.
 *
 * @param loginTimes - Unordered map containing login time records for each user.
 * @param authorizedUsers - Unordered map containing authorizedUser IDs to be
 *                          referenced.
 * @param userID - User ID to be checked for a login time violation.
 *
 * @return True if there is a violation. False if not.
 */
bool frequencyHacking(LoginTimes& loginTimes,
    const LookupMap& authorizedUsers, const std::string& userID) {
    bool isViolation = false;
    if (authorizedUsers.find(userID) == authorizedUsers.end()) {
        if (loginTimes[userID].size() > 3) {
            size_t i = loginTimes[userID].size() - 1;
            if (loginTimes[userID][i] - loginTimes[userID][i - 3] <= 20) {
                isViolation = true;
            }
        }
    }
    return isViolation;
}

/**
 * Helper method to fill out an unordered map with the login time
 * records for each user ID.
 * 
 * @param month - Strings containing the month
 * @param day - Strings containing the day
 * @param time - Strings containing the time
 * @param userID - Strings containing the userID
 */
void loginTime(const std::string& month, const std::string& day,
    const std::string& time, const std::string& userID,
    LoginTimes& loginTimes) {
    std::string timeStamp = month + " " + day + " " + time;
    long seconds = toSeconds(timeStamp);
    if (loginTimes.find(userID) == loginTimes.end()) {
        std::vector<long> vec = {seconds};
        loginTimes[userID] = vec;
    } else {
        loginTimes[userID].push_back(seconds);
    }
}
/**
 * Process login logs and detects possible hacking attempts due to 
 * login by a banned IP address or by excessive login frequency from
 * a single unauthorized user.
 * 
 * Print the results of the hack detection
 */
void processLogs(std::istream& is, const LookupMap& bannedIPs,
    const LookupMap& authorizedUsers) {
    std::string line, month, day, time, userID, ip, dummy;
    int lineCount = 0, hackCount = 0;
    LoginTimes loginTimes;
    while (std::getline(is, line)) {
        std::istringstream(line) >> month >> day >> time >> dummy >> dummy
            >> dummy >> dummy >> dummy >> userID >> dummy >> ip;
        if (bannedIPs.find(ip) != bannedIPs.end()) {
            hackCount++;
            std::cout << "Hacking due to banned IP. Line: " << line << '\n';
        } else {
            loginTime(month, day, time, userID, loginTimes);
            if (frequencyHacking(loginTimes, authorizedUsers, userID)) {
                hackCount++;
                std::cout << "Hacking due to frequency. Line: " << line << '\n';
            }
        }
        lineCount++;
    }
    std::cout << "Processed " << lineCount << " lines. Found " << hackCount
        << " possible hacking attempts." << '\n';
}

/**
 * Helper method to break down a URL into hostname, port and path.
 * @param url A string with the given URL.
 * @return a tuple with 3 strings. 
 * The 3 strings in the tuple are: hostname, port, and path.
 */
std::tuple<std::string, 
            std::string, std::string> breakDownURL(const std::string& url) {
    // The values to be returned.
    std::string hostName, port = "80", path = "/";
    std::size_t start = url.find("//") + 2;
    std::size_t end;
    hostName = url.substr(start);
    if (hostName.find(':') != std::string::npos) {
        end = hostName.find(':');
        port = hostName.substr(end + 1);
        port = port.substr(0, port.find('/'));
    } else {
        end = hostName.find('/');
    }
    path = hostName.substr(hostName.find('/'));
    hostName = hostName.substr(0, end);
    return { hostName, port, path };
}

/**
 * The main function that uses different helper methods to download and process
 * log entries from the given URL and detect potential hacking attempts.
 *
 * \param[in] argc The number of command-line arguments.  This program
 * requires exactly one command-line argument.
 *
 * \param[in] argv The actual command-line argument. This should be an URL.
 */
int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cout << "Specify URL from where logs are to be obtained.\n";
        return 1;
    }
    const std::string url = argv[1];
    tcp::iostream is;  // stream to read ssh logs
    std::string host, port, path;
    std::tie(host, port, path) = breakDownURL(url);
    setupDownload(host, path, is);
    // Skips over html lines
    for (std::string hdr; std::getline(is, hdr) && !hdr.empty()
            && hdr != "\r";) {
    }
    LookupMap bannedIPs = loadLookup("banned_ips.txt");
    LookupMap authorizedUsers = loadLookup("authorized_users.txt");
    processLogs(is, bannedIPs, authorizedUsers);
    return 0;
}

// End of source code
