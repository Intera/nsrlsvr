#include <dirent.h>
#include "intera_extension.h"
using std::endl;
using std::make_pair;
using std::make_tuple;

string hashes_location_ext{PKGDATADIR "/hashes"};
vector<sha1> hash_set_sha1;
vector<sha256> hash_set_sha256;

enum HashFileFormat {
  hash_file_format_invalid,
  hash_file_format_combined,
  hash_file_format_md5,
  hash_file_format_nsrl,
  hash_file_format_sha1,
  hash_file_format_sha256
};

static bool string_starts_with(const std::string& str, const std::string& prefix) {
  return str.size() >= prefix.size() && 0 == str.compare(0, prefix.size(), prefix);
}

static bool string_ends_with(const std::string& str, const std::string& suffix) {
  return str.size() >= suffix.size() && 0 == str.compare(str.size() - suffix.size(), suffix.size(), suffix);
}

bool operator<(const sha1& a, const sha1& b) {
  if (std::get<0>(a) < std::get<0>(b)) return true;
  if (std::get<0>(a) > std::get<0>(b)) return false;
  if (std::get<1>(a) < std::get<1>(b)) return true;
  if (std::get<1>(a) > std::get<1>(b)) return false;
  if (std::get<2>(a) < std::get<2>(b)) return true;
  if (std::get<2>(a) > std::get<2>(b)) return false;
  return false;
}

bool operator<(const sha256& a, const sha256& b) {
  if (std::get<0>(a) < std::get<0>(b)) return true;
  if (std::get<0>(a) > std::get<0>(b)) return false;
  if (std::get<1>(a) < std::get<1>(b)) return true;
  if (std::get<1>(a) > std::get<1>(b)) return false;
  if (std::get<2>(a) < std::get<2>(b)) return true;
  if (std::get<2>(a) > std::get<2>(b)) return false;
  if (std::get<3>(a) < std::get<3>(b)) return true;
  if (std::get<3>(a) > std::get<3>(b)) return false;
  return false;
}

pair64 to_md5(const string& input) {
  auto as = string(input.cbegin(), input.cbegin() + 16);
  auto bs = string(input.cbegin() + 16, input.cend());
  auto a = std::strtoull(as.c_str(), nullptr, 16);
  auto b = std::strtoull(bs.c_str(), nullptr, 16);
  return make_pair(a, b);
}

sha1 to_sha1(const string& input) {
  auto as = string(input.cbegin(), input.cbegin() + 16);
  auto bs = string(input.cbegin() + 16, input.cbegin() + 32);
  auto cs = string(input.cbegin() + 32, input.cend());
  auto a = std::strtoull(as.c_str(), nullptr, 16);
  auto b = std::strtoull(bs.c_str(), nullptr, 16);
  auto c = std::strtoul(cs.c_str(), nullptr, 8);
  return make_tuple(a, b, c);
}

sha256 to_sha256(const string& input) {
  auto as = string(input.cbegin(), input.cbegin() + 16);
  auto bs = string(input.cbegin() + 16, input.cbegin() + 32);
  auto cs = string(input.cbegin() + 32, input.cbegin() + 48);
  auto ds = string(input.cbegin() + 48, input.cend());
  auto a = std::strtoull(as.c_str(), nullptr, 16);
  auto b = std::strtoull(bs.c_str(), nullptr, 16);
  auto c = std::strtoull(cs.c_str(), nullptr, 16);
  auto d = std::strtoull(ds.c_str(), nullptr, 16);
  return make_tuple(a, b, c, d);
}

void log_loaded_count(uint64_t count) {
  log(LogLevel::INFO, string("loaded ") + to_string(count) + string(" hashes"));
}

uint64_t load_file_format_combined(ifstream& infile) {
  // skip header
  const regex hash_re{"^([A-F0-9]{32})?;([A-F0-9]{40})?;([A-F0-9]{64})?;.*"};
  uint64_t count = 0;
  while (infile) {
    string line;
    getline(infile, line);
    if (string_starts_with(line, "MD5;")) break;
  }
  // read content
  while (infile) {
    string line;
    getline(infile, line);
    if (0 == line.size()) continue;
    transform(line.begin(), line.end(), line.begin(), ::toupper);
    std::smatch matches;
    if (!std::regex_search(line, matches, hash_re)) {
      log(LogLevel::ALERT, "invalid line \"" + line + "\"");
      continue;
    }
    if (matches[1].length()) {
      hash_set.emplace_back(to_md5(matches[1].str()));
      count += 1;
    }
    if (matches[2].length()) {
      hash_set_sha1.emplace_back(to_sha1(matches[2].str()));
      count += 1;
    }
    if (matches[3].length()) {
      hash_set_sha256.emplace_back(to_sha256(matches[3].str()));
      count += 1;
    }
  }
  return count;
}

uint64_t load_file_format_md5(ifstream& infile) {
  // newline separated list of md5 sums, with optional ignored data separated by a semicolon
  const regex hash_re{"^[A-Fa-f0-9]{32}($|(;.*))"};
  uint64_t count = 0;
  while (infile) {
    string line;
    getline(infile, line);
    if (0 == line.size()) continue;
    if (!regex_match(line.cbegin(), line.cend(), hash_re)) {
      if (string_starts_with(line, "MD5;")) continue;
      log(LogLevel::ALERT, "invalid line \"" + line + "\"");
      continue;
    }
    transform(line.begin(), line.begin() + 32, line.begin(), ::toupper);
    hash_set.emplace_back(to_pair64(line.substr(0, 32)));
    count += 1;
  }
  return count;
}

uint64_t load_file_format_nsrl(ifstream& infile) {
  return 0;
}

uint64_t load_file_format_sha1(ifstream& infile) {
  return 0;
}

uint64_t load_file_format_sha256(ifstream& infile) {
  return 0;
}

uint64_t load_file(string path, HashFileFormat format) {
  uint64_t count;
  log(LogLevel::INFO, string("reading file \"") + path + string("\""));
  // open file
  ifstream infile{path.c_str()};
  if (not infile) {
    log(LogLevel::ALERT, "couldn't open hashes file " + hashes_location);
    exit(EXIT_FAILURE);
  }
  switch (format) {
  case hash_file_format_combined: count = load_file_format_combined(infile); break;
  case hash_file_format_md5: count = load_file_format_md5(infile); break;
  case hash_file_format_nsrl: count = load_file_format_nsrl(infile); break;
  case hash_file_format_sha1: count = load_file_format_sha1(infile); break;
  case hash_file_format_sha256: count = load_file_format_sha256(infile); break;
  }
  // close file
  infile.close();
  log_loaded_count(count);
  // sort, for binary_search to work correctly
  sort(hash_set.begin(), hash_set.end());
  sort(hash_set_sha1.begin(), hash_set_sha1.end());
  sort(hash_set_sha256.begin(), hash_set_sha256.end());
  return count;
}

enum HashFileFormat detect_file_format(string file_name) {
  if (string_ends_with(file_name, ".combined")) return hash_file_format_combined;
  else if (string_ends_with(file_name, ".md5")) return hash_file_format_md5;
  else if (string_ends_with(file_name, ".nsrl")) return hash_file_format_nsrl;
  else if (string_ends_with(file_name, ".sha1")) return hash_file_format_sha1;
  else if (string_ends_with(file_name, ".sha256")) return hash_file_format_sha256;
  else return hash_file_format_invalid;
}

void load_directory(string path) {
  uint64_t count = 0;
  DIR *dir;
  struct dirent *entry;
  if (0 != (dir = opendir(hashes_location.c_str()))) {
    while (0 != (entry = readdir(dir))) {
      HashFileFormat format = detect_file_format(entry->d_name);
      if (hash_file_format_invalid == format) continue;
      string full_path(path);
      full_path.append("/").append(entry->d_name);
      count += load_file(full_path, format);
    }
    closedir(dir);
    log_loaded_count(count);
  }
  else {
    log(LogLevel::ALERT, "couldn't open hash file directory");
    exit(EXIT_FAILURE);
  }
}

void load_hashes_ext() {
  // create hash_set arrays
  try {
    hash_set.reserve(100000000);
    hash_set_sha1.reserve(100000000);
    hash_set_sha256.reserve(100000000);
  } catch (std::bad_alloc&) {
    log(LogLevel::ALERT, "couldn't reserve enough memory");
    exit(EXIT_FAILURE);
  }
  // load all supported files in directory
  load_directory(hashes_location);
}
