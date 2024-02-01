# Sniff Cookies

[![Test](https://github.com/SkypLabs/sniff-cookies/actions/workflows/test.yml/badge.svg?branch=develop)](https://github.com/SkypLabs/sniff-cookies/actions/workflows/test.yml)

Sniff Cookies, as its name implies, allows to display the HTTP cookies passing
through the network your NIC is connected to.

The Git repository has been migrated from GitHub to [Codeberg][codeberg-repo].
Activities on GitHub (e.g. commits, issues) are mirrored to Codeberg.

## Installation

Pre-compiled and packaged versions are available for download on the
[releases][releases] page.

If you want to build the latest version yourself, make sure to have the
dependencies listed in [`packagecore.yaml`](packagecore.yaml) installed (both
development and runtime dependencies) and then:

    ./autogen.sh
    ./configure
    make
    make install # as root

## How to

  Usage: sniff-cookies [OPTION...]
  Allows to display the HTTP cookies passing through the network

    -C, --csv                  Display cookies as CSV data
    -i, --interface=INTERFACE  Specify the network interface to use
    -p, --port=PORT            Specify the network port to listen (default: 80)
    -?, --help                 Give this help list
        --usage                Give a short usage message
    -V, --version              Print program version

  Mandatory or optional arguments to long options are also mandatory or optional
  for any corresponding short options.

  Report bugs to <skyper@skyplabs.net>.

Here is an example of use:

    sniff-cookies -i eth0 -p 8080

## Output

### Default

Here is an example of the default output:

  Host: www.html-kit.com
  IP sources: 192.168.20.22
  Resource: /tools/cookietester/
  Request type: GET

  TestCookie_Name_201607045556 = TestCookie_Value_155556
  TestCookie_Name_201607045620 = TestCookie_Value_155620

### CSV

With option `-C`, each output line will follow the following structure:

    host;ip_source;resource_requested;request_type;cookie_1_name;cookie_1_value;cookie_2_name;cookie_2_value;...

Here is an example:

    www.html-kit.com;192.168.20.22;/tools/cookietester/;GET;TestCookie_Name_201607045556;TestCookie_Value_155556;TestCookie_Name_201607045620;TestCookie_Value_155620

## Development

### Formatting code

The C code can be automatically formatted using [ClangFormat][clang-format]:

  make format

### Bumping the version number

Once ready to release a new version, the version number must be changed in:

* `configure.ac`
* `src/sniff_cookies.c`

## License

[GPL version 3][gpl-v3]

 [clang-format]: https://clang.llvm.org/docs/ClangFormat.html
 [codeberg-repo]: https://codeberg.org/Skyper/sniff-cookies
 [gpl-v3]: https://www.gnu.org/licenses/gpl.txt
 [releases]: https://codeberg.org/Skyper/sniff-cookies/releases
