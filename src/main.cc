/*
Copyright (c) 2015-2019, Robert J. Hansen <rjh@sixdemonbag.org>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#include "main.h"
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <algorithm>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fstream>
#include <iostream>
#include <regex>
#include <vector>

using boost::asio::ip::tcp;
using boost::program_options::notify;
using boost::program_options::options_description;
using boost::program_options::parse_command_line;
using boost::program_options::store;
using boost::program_options::value;
using boost::program_options::variables_map;
using std::cerr;
using std::cout;
using std::fill;
using std::getline;
using std::ifstream;
using std::pair;
using std::regex;
using std::sort;
using std::stoi;
using std::string;
using std::to_string;
using std::transform;
using std::vector;

namespace {
vector<pair64> hash_set;
string hashes_location{PKGDATADIR "/hashes.txt"};
uint16_t port{9120};
bool dry_run{false};

/** Attempts to load a set of MD5 hashes from disk.
 * Each line must be either blank or 32 hexadecimal digits.  If the
 * file doesn't conform to this, nsrlsvr will abort and display an
 * error message to the log.
 */
void load_hashes() {
  const regex md5_re{"^[A-Fa-f0-9]{32}$"};
  uint32_t hash_count{0};
  ifstream infile{hashes_location.c_str()};

  // As of this writing, the full RDS had about 81 million entries.
  // When a vector needs to grow, it normally does so by doubling
  // the former allocation -- so after this, the next stop is a
  // 200 million allocation (@ 16 bytes per, or 3.2 GB).  If you're
  // maintaining this code, try to keep the reserve a few million
  // larger than the RDS currently is, to give yourself room to
  // grow without a vector realloc.
  //
  // Failure to reserve this block of memory is non-recoverable.
  // Don't even try.  Just log the error and bail out.  Let the end
  // user worry about installing more RAM.
  try {
    hash_set.reserve(100000000);
  } catch (std::bad_alloc&) {
    log(LogLevel::ALERT, "couldn't reserve enough memory");
    exit(EXIT_FAILURE);
  }

  if (not infile) {
    log(LogLevel::ALERT, "couldn't open hashes file " + hashes_location);
    exit(EXIT_FAILURE);
  }

  while (infile) {
    string line;
    getline(infile, line);
    transform(line.begin(), line.end(), line.begin(), ::toupper);
    if (0 == line.size()) continue;

    if (!regex_match(line.cbegin(), line.cend(), md5_re)) {
      log(LogLevel::ALERT, "hash file appears corrupt!  Loading no hashes.");
      log(LogLevel::ALERT, "offending line is: " + line);
      log(LogLevel::ALERT, "shutting down!");
      exit(EXIT_FAILURE);
    }

    try {
      // .emplace_back is the C++11 improvement over the old
      // vector.push_back.  It has the benefit of not needing
      // to construct a temporary to hold the value; it can
      // just construct-in-place.  For 40 million values, that
      // can be significant.
      //
      // Note that if the vector runs out of reserved room it
      // will attempt to make a new allocation double the size
      // of the last.  That means the application will at least
      // briefly need *three times* the expected RAM -- one for
      // the data set and two for the newly-allocated chunk.
      // Given we're talking about multiple gigs of RAM, this
      // .emplace_back needs to consider the possibility of a
      // RAM allocation failure.
      hash_set.emplace_back(to_pair64(line));
      hash_count += 1;
      if (0 == hash_count % 1000000) {
        string howmany{to_string(hash_count / 1000000)};
        log(LogLevel::INFO, "loaded " + howmany + " million hashes");
      }
    } catch (std::bad_alloc&) {
      log(LogLevel::ALERT, "couldn't allocate enough memory");
      exit(EXIT_FAILURE);
    }
  }
  string howmany{to_string(hash_count)};
  log(LogLevel::INFO, "read in " + howmany + " hashes");

  infile.close();

  sort(hash_set.begin(), hash_set.end());

  if (hash_set.size() > 1) {
    log(LogLevel::INFO, "ensuring no duplicates");
    for (auto iter = (hash_set.cbegin() + 1); iter != hash_set.cend(); ++iter) {
      if (*(iter - 1) == *iter) {
        log(LogLevel::ALERT,
	    string("Line #") + std::to_string(iter - hash_set.cbegin()) +
            "hash file contains duplicates -- "
            "shutting down!");
        exit(EXIT_FAILURE);
      }
    }
  }

  log(LogLevel::INFO, "successfully loaded hashes");
}

/** Converts this process into a well-behaved UNIX daemon.*/
void daemonize() {
  /* Nothing in here should be surprising.  If it is, then please
   check the standard literature to ensure you understand how a
   daemon is supposed to work. */
  const auto pid = fork();
  if (0 > pid) {
    log(LogLevel::WARN, "couldn't fork!");
    exit(EXIT_FAILURE);
  } else if (0 < pid) {
    exit(EXIT_SUCCESS);
  }
  log(LogLevel::INFO, "daemon started");

  umask(0);

  if (0 > setsid()) {
    log(LogLevel::WARN, "couldn't set sid");
    exit(EXIT_FAILURE);
  }

  if (0 > chdir("/")) {
    log(LogLevel::WARN, "couldn't chdir to root");
    exit(EXIT_FAILURE);
  }

  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
}

/** Parse command-line options.
    @param argc argc from main()
    @param argv argv from main()
*/
void parse_options(int argc, char* argv[]) {
  std::array<char, PATH_MAX> filename_buffer;
  char* filepath{&filename_buffer[0]};
  fill(filename_buffer.begin(), filename_buffer.end(), 0);
  options_description options{"nsrlsvr options"};
  options.add_options()("help,h", "Help screen")("version,v",
                                                 "Display package version")(
      "bug-report,b", "Display bug reporting information")(
      "file,f", value<string>()->default_value(PKGDATADIR "/hashes.txt"),
      "hash file")("port,p", value<uint16_t>()->default_value(9120), "port")(
      "dry-run", "test configuration");
  variables_map vm;
  store(parse_command_line(argc, argv, options), vm);

  dry_run = vm.count("dry-run") ? true : false;

  if (vm.count("help")) {
    cout << options << "\n";
    exit(EXIT_SUCCESS);
  }
  if (vm.count("version")) {
    cout << "nsrlsvr version " << PACKAGE_VERSION
         << "\n\n"
            "This program is released under the ISC License.\n";
    exit(EXIT_SUCCESS);
  }
  if (vm.count("bug-report")) {
    cout << "To file a bug report, visit "
            "https://github.com/rjhansen/nsrlsvr/issues\n";
    exit(EXIT_SUCCESS);
  }
  port = vm["port"].as<uint16_t>();
  string relpath = vm["file"].as<string>();
  if (nullptr == (filepath = realpath(relpath.c_str(), filepath))) {
    switch (errno) {
      case EACCES:
        cerr << "Could not access file path " << relpath
             << "\n(Do you have read privileges?)\n";
        break;
      case EINVAL:
        cerr << "Somehow, the system believes the file path passed to it\n"
                "is null.  This is weird and probably a bug.  Please report\n"
                "it!\n";
        break;
      case EIO:
        cerr << "An I/O error occurred while reading " << relpath << "\n";
        break;
      case ELOOP:
        cerr << "Too many symbolic links were found while translating "
             << relpath << " into an absolute path.\n";
        break;
      case ENAMETOOLONG:
        cerr << "The file path " << relpath << " is too long.\n";
        break;
      case ENOENT:
        cerr << "The file " << relpath << " could not be found.\n";
        break;
      case ENOMEM:
        cerr << "Strangely, the system ran out of memory while processing\n"
                "your request.  This is probably a bug in nsrlsvr.\n";
        break;
      case ENOTDIR:
        cerr << "A component of the file path " << relpath
             << " is not a directory.";
        break;
      default:
        cerr << "... wtfbbq?  This should never trip.  It's an nsrlsvr bug.\n";
        break;
    }
    exit(EXIT_FAILURE);
  }
  hashes_location = string(filepath);
  if (not ifstream(hashes_location.c_str())) {
    cerr << "Could not open " + hashes_location + " for reading.\n";
    exit(EXIT_FAILURE);
  }
}
}  // namespace

/** The set of all loaded hashes, represented as a const reference. */
const vector<pair64>& hashes{hash_set};

/** Writes to syslog with the given priority level.

    @param level The priority of the message
    @param msg The message to write
*/
void log(const LogLevel level, const string&& msg) {
  if (dry_run)
    cerr << msg << "\n";
  else
    syslog(LOG_MAKEPRI(LOG_USER, static_cast<int>(level)), "%s", msg.c_str());
}

/** Entry point for the application.

    @param argc The number of command-line arguments
    @param argv Command-line arguments
*/
int main(int argc, char* argv[]) {
  static_assert(sizeof(unsigned long long) == 8,
                "wait, what kind of system is this?");
  parse_options(argc, argv);

  if (!dry_run) daemonize();

  load_hashes();

  // The following line helps avoid zombie processes.  Normally parents
  // need to reap their children in order to prevent zombie processes;
  // if SIGCHLD is set to SIG_IGN, though, the processes can terminate
  // normally.
  signal(SIGCHLD, SIG_IGN);

  if (dry_run) return EXIT_SUCCESS;

  boost::asio::io_service io_service;
  const char* listen_address = "::";
  boost::asio::ip::address address = boost::asio::ip::address::from_string(listen_address);
  tcp::endpoint endpoint(address, port);
  tcp::acceptor acceptor(io_service, endpoint.protocol());
  if (endpoint.protocol() == tcp::v6()) {
    boost::system::error_code ec;
    acceptor.set_option(boost::asio::ip::v6_only(false), ec);
  }
  acceptor.bind(endpoint);
  acceptor.listen();

  while (true) {
    tcp::iostream stream;
    boost::system::error_code error;
    acceptor.accept(*stream.rdbuf(), error);

    if (error) {
      continue;
    }
    string ipaddr = stream.socket().remote_endpoint().address().to_string();
    log(LogLevel::ALERT, string("accepted a client: ") + ipaddr);

    if (0 == fork()) {
      log(LogLevel::ALERT, "calling handle_client");
      handle_client(stream);
      return 0;
    }
  }

  // Note that as is normal for daemons, the exit point is never
  // reached.  This application does not normally terminate.
  return EXIT_SUCCESS;
}
