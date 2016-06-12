# Sniff Cookies

[![Build Status](https://travis-ci.org/SkypLabs/sniff-cookies.svg)](https://travis-ci.org/SkypLabs/sniff-cookies)

This program allows to display the HTTP cookies passing through the network which your NIC is connected.

## Dependencies

 * [libpcap][1]

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
    Allows to display HTTP cookies passing through the network

      -i, --interface=INTERFACE  Specify the network interface to use
      -?, --help                 Give this help list
          --usage                Give a short usage message
      -V, --version              Print program version

    Mandatory or optional arguments to long options are also mandatory or optional
    for any corresponding short options.

    Report bugs to <skyper@skyplabs.net>.

## License

[GPL version 3][2]

  [1]: http://www.tcpdump.org "Official web site of tcpdump and libpcap"
  [2]: https://www.gnu.org/licenses/gpl.txt "GPL version 3"
