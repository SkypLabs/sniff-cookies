# Sniff Cookies

[![Build Status](https://travis-ci.org/SkypLabs/sniff-cookies.svg)](https://travis-ci.org/SkypLabs/sniff-cookies) [![Codacy Badge](https://api.codacy.com/project/badge/Grade/729dc0fae9bf4581ba2c8ce0dd2cd999)](https://www.codacy.com/app/skyper/sniff-cookies?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=SkypLabs/sniff-cookies&amp;utm_campaign=Badge_Grade)

This program allows to display the HTTP cookies passing through the network which your NIC is connected.

## Dependencies

 * [libpcap][tcpdump]

### On Fedora

    dnf install make automake gcc libpcap libpcap-devel

### On Debian

    apt-get install make automake gcc libpcap0.8 libpcap-dev

## Installation

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

	Host : www.html-kit.com
	IP sources : 192.168.20.22
	Resource : /tools/cookietester/
	Request type : GET

	TestCookie_Name_201607045556 = TestCookie_Value_155556
	TestCookie_Name_201607045620 = TestCookie_Value_155620

### CSV

With option *-C*, each output line will look like this:

    host;ip_source;resource_requested;request_type;cookie_1_name;cookie_1_value;cookie_2_name;cookie_2_value;...

Here is an example:

    www.html-kit.com;192.168.20.22;/tools/cookietester/;GET;TestCookie_Name_201607045556;TestCookie_Value_155556;TestCookie_Name_201607045620;TestCookie_Value_155620

## License

[GPL version 3][GPLv3]

 [tcpdump]: http://www.tcpdump.org "Official web site of tcpdump and libpcap"
 [GPLv3]: https://www.gnu.org/licenses/gpl.txt "GPL version 3"
