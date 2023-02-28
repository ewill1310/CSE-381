// Copyright 2023 - Evan Williams
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <utility>
#include <vector>
#include <algorithm>
#include <numeric>
#include <unordered_map>

// It is ok to use the following namespace delarations in C++ source
// files only. They must never be used in header files.

using namespace std;
using namespace std::string_literals;

/** This method is to be used to gather all member info from the group
 * std::istream& line - The input stream to read the group line
 * Returns a completed map of the users in a group and their info
 */
std::unordered_map<int, std::string> memberInfo(std::istream& line) {
    std::string copy;
    std::unordered_map<int, std::string> userMap;
    while (std::getline(line, copy)) {
        std::replace(copy.begin(), copy.end(), ':', ' ');
        std::istringstream is(copy);
        std::string name, pass;
        int id;
        is >> name >> pass >> id;
        userMap[id] = name;
    }
    return userMap;
}

/** This method is used to read the group line and gather the members
* std::istream& line - The input stream used to read the group line
* Returns a map of group ids matching to member ids
*/
std::unordered_map<int, std::vector<int>> groupMembers(std::istream& line) {
    std::string copy;
    std::unordered_map<int, std::vector<int>> userIDs;
    while (std::getline(line, copy)) {
        std::replace(copy.begin(), copy.end(), ':', ' ');
        std::replace(copy.begin(), copy.end(), ',', ' ');
        std::istringstream is(copy);
        std::string group, pass;
        int gid, id;
        is >> group >> pass >> gid;
        std::vector<int> uids;
        while (is >> id) {
             uids.push_back(id);
        }
        userIDs[gid] = uids;
    }
    return userIDs;
}

/** This method is used to process the inputs from our files
* memberInfo and passwd, and will fill out maps of info for memberInfo and
* group members
* std::vector<int> groupIds - a list of group ids
*/
void processInput(std::vector<int> groupIds) {
    std::ifstream groupsFile("groups"); 
    std::ifstream groupsFile2("groups");
    std::ifstream passFile("passwd");
    std::unordered_map<int, std::string> memberUID;
    std::unordered_map<int, std::vector<int>> members;
    std::unordered_map<int, std::string> theGroups;
    memberUID = memberInfo(passFile);
    members = groupMembers(groupsFile);
    theGroups = memberInfo(groupsFile2);
    for (size_t i = 0; i < (groupIds.size()); i++) {
        if (theGroups.find(groupIds[i]) == theGroups.end()) {
            std::cout << groupIds[i] << " = Group not found.\n";
        } else {
            string groupID = theGroups.at(groupIds[i]);
            std::vector<int> uniqueID = members.at(groupIds[i]);
            std::cout << groupIds[i] << " = " << groupID << ":";
            for (int i = 0; i < static_cast<int>(uniqueID.size()); i++) {
                string name = memberUID.at(uniqueID[i]);
                std::cout << " " << name << "(" << uniqueID[i] << ")";
            }
            std::cout << "\n";
        }
    }
}

/** This method runs our code and will return info about memberInfo and members
* For each group id present in the command line program call
*/
int main(int argc, char *argv[]) {
    int totalInputs = argc;
    std::vector<int> groupIds;
    // Adds the user wanted group ids from the commandline to a vector
    for (int i = 1; i < totalInputs; i++) {
       groupIds.push_back(atoi(argv[i]));
    }
    processInput(groupIds);
    return 0;
}

// End of source code
