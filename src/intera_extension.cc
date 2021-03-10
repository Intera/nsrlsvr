#include <dirent.h>
#include <inttypes.h>
using sha1 = std::tuple<uint64_t, uint64_t, uint32_t>;
using sha256 = std::tuple<uint64_t, uint64_t, uint64_t, uint64_t>;
using std::binary_search;
using std::endl;
using std::make_pair;
using std::make_tuple;
using std::stringstream;
using std::to_string;
using boost::char_separator;
using boost::tokenizer;

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
  auto c = std::strtoul(cs.c_str(), nullptr, 16);
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

void log_invalid_line(string line) {
  log(LogLevel::ALERT, "invalid line \"" + line + "\"");
}

uint64_t load_file_format_combined(ifstream& infile) {
  // skip header
  const regex hash_re{"^([A-F0-9]{32})?\\W([A-F0-9]{40})?\\W([A-F0-9]{64})?($|(\\W.*))"};
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
    if (32 > line.size()) continue;
    transform(line.begin(), line.end(), line.begin(), ::toupper);
    std::smatch matches;
    if (!std::regex_search(line, matches, hash_re)) {
      log_invalid_line(line);
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

uint64_t load_file_format_nsrl(ifstream& infile) {
  // "SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"
  // "00000079FD7AAC9B2F9C988C50750E1F50B27EB5","8ED4B4ED952526D89899E723F3488DE4","7A5407CA","wow64_microsoft-windows-i...
  const regex hash_re{"^\"([A-F0-9]{40})\",\"([A-F0-9]{32})\",.*"};
  uint64_t count = 0;
  string line;
  // skip header
  getline(infile, line);
  // read content
  while (infile) {
    getline(infile, line);
    if (77 > line.size()) continue;
    transform(line.begin(), line.begin() + 77, line.begin(), ::toupper);
    std::smatch matches;
    if (!std::regex_search(line, matches, hash_re)) {
      log_invalid_line(line);
      continue;
    }
    if (matches[1].length()) {
      hash_set_sha1.emplace_back(to_sha1(matches[1].str()));
      count += 1;
    }
    if (matches[2].length()) {
      hash_set.emplace_back(to_md5(matches[2].str()));
      count += 1;
    }
  }
  return count;
}

uint64_t load_file_format_md5(ifstream& infile) {
  // newline separated list of md5 sums, with optional ignored data separated by a semicolon
  const regex hash_re{"^[A-F0-9]{32}($|(\\W.*))"};
  uint64_t count = 0;
  while (infile) {
    string line;
    getline(infile, line);
    if (32 > line.size()) continue;
    transform(line.begin(), line.begin() + 32, line.begin(), ::toupper);
    if (!regex_match(line.cbegin(), line.cend(), hash_re)) {
      if (string_starts_with(line, "MD5;")) continue;
      log_invalid_line(line);
      continue;
    }
    hash_set.emplace_back(to_md5(line.substr(0, 32)));
    count += 1;
  }
  return count;
}

uint64_t load_file_format_sha1(ifstream& infile) {
  const regex hash_re{"^[A-F0-9]{40}($|(\\W.*))"};
  uint64_t count = 0;
  while (infile) {
    string line;
    getline(infile, line);
    if (40 > line.size()) continue;
    transform(line.begin(), line.begin() + 40, line.begin(), ::toupper);
    if (!regex_match(line.cbegin(), line.cend(), hash_re)) {
      if (string_starts_with(line, "SHA1;")) continue;
      log_invalid_line(line);
      continue;
    }
    hash_set_sha1.emplace_back(to_sha1(line.substr(0, 40)));
    count += 1;
  }
  return count;
}

uint64_t load_file_format_sha256(ifstream& infile) {
  const regex hash_re{"^[A-F0-9]{64}($|(\\W.*))"};
  uint64_t count = 0;
  while (infile) {
    string line;
    getline(infile, line);
    if (64 > line.size()) continue;
    transform(line.begin(), line.begin() + 64, line.begin(), ::toupper);
    if (!regex_match(line.cbegin(), line.cend(), hash_re)) {
      if (string_starts_with(line, "SHA256;")) continue;
      log_invalid_line(line);
      continue;
    }
    hash_set_sha256.emplace_back(to_sha256(line.substr(0, 64)));
    count += 1;
  }
  return count;
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

bool is_present_in_hashes_md5(const string& hash) {
  return binary_search(hash_set.cbegin(), hash_set.cend(), to_pair64(hash));
}

bool is_present_in_hashes_sha1(const string& hash) {
  return binary_search(hash_set_sha1.cbegin(), hash_set_sha1.cend(), to_sha1(hash));
}

bool is_present_in_hashes_sha256(const string& hash) {
  return binary_search(hash_set_sha256.cbegin(), hash_set_sha256.cend(), to_sha256(hash));
}

auto tokenize_ext(const string&& line) {
  vector<string> rv;
  char_separator<char> sep(" ");
  tokenizer<char_separator<char>> tokens(line, sep);
  for (const auto& t : tokens) {
    rv.emplace_back(t);
  }
  return rv;
}

void handle_client_ext(tcp::iostream& stream) {
  const string ipaddr = stream.socket().remote_endpoint().address().to_string();
  unsigned long long queries = 0;
  try {
    bool byebye = false;
    while (stream && (! byebye)) {
      string line;
      getline(stream, line);
      // trim leading/following whitespace
      auto end_ws = line.find_last_not_of("\t\n\v\f\r ");
      // trips on the empty string, or a string of pure whitespace
      if (line.size() == 0 || end_ws == string::npos) break;
      auto head_iter = line.cbegin() + line.find_first_not_of("\t\n\v\f\r ");
      auto end_iter = line.cbegin() + end_ws + 1;
      auto commands = tokenize_ext(string(head_iter, end_iter));
      if ("query" == commands.at(0)) {
        stringstream rv;
        string format = commands.at(1);
        rv << "OK ";
        if ("sha1" == format) {
          for (size_t idx = 2; idx < commands.size(); ++idx)
            rv << (is_present_in_hashes_sha1(commands.at(idx)) ? "1" : "0");
          queries += (commands.size() - 2);
        }
        else if ("sha256" == format) {
          for (size_t idx = 2; idx < commands.size(); ++idx)
            rv << (is_present_in_hashes_sha256(commands.at(idx)) ? "1" : "0");
          queries += (commands.size() - 2);
        }
        else {
          for (size_t idx = 1; idx < commands.size(); ++idx)
            rv << (is_present_in_hashes_md5(commands.at(idx)) ? "1" : "0");
          queries += (commands.size() - 1);
        }
        rv << "\r\n";
        stream << rv.str();
      }
      else if ("Version:" == commands.at(0)) stream << "OK\r\n";
      else if ("bye" == commands.at(0)) byebye = true;
      else if ("status" == commands.at(0)) stream << "NOT SUPPORTED\r\n";
      else if ("upshift" == commands.at(0)) stream << "NOT OK\r\n";
      else if ("downshift" == commands.at(0)) stream << "NOT OK\r\n";
      else {
        stream << "NOT OK\r\n";
        byebye = true;
      }
    }
  } catch (std::exception& e) {
    log(LogLevel::ALERT, string("Error: ") + e.what());
  }

  stringstream status_msg;
  status_msg << ipaddr << " closed session after " << queries << " queries";
  log(LogLevel::ALERT, status_msg.str());
}
