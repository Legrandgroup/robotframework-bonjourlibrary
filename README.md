BonjourLibrary for Robot Framework
==================================


## Introduction

BonjourLibrary is a [Robot Framework](http://robotframework.org) test
library for testing devices announcing services using the Bonjour/mDNS protocol.
It will browse the Bonjour services on the network and allow Robot Framework to
use all information provided by the Bonjour/mDNS protocol via Robot Framework
keywords.

This library currently only works for Linux platforms.

In order to browse Bonjour devices, you will need to install the command
`avahi-browse` on the machine where this library is running (on most
distributions, this comes with package avahi-utils).

By default, this library resolves IP addresses to MAC addresses. For this, it
also requires the arping utility (and will most often also require sudo
privileges to run arping)

BonjourLibrary is open source software licensed under
[Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0.html).

## For users

### Prerequisites

This library requires the following executables to be accessible:
- avahi-browse
- arping (if IP to MAC address is required)

### Installation

To install this libary, run the `./setup.py install` command locate inside the
repository.

### Robot Framework keywords

The following RobotFramework keywords are made available by this library:
Note: it is advised to go directly inside the python code's docstrings (or via
RIDE's online help) to get a detailed description of keywords).

#### `Get Services`

*Retrieve the list of published Bonjour services*

The first optional argument contains the service type to filter (eg: _http._tcp)
The second optional argument contains the network interface to filter (eg: eth1)
The third optional argument contains the IP version to filer (eg: ipv4)

Returns an array of services found. Each entry of the array contains a tuple
describing one service. The tuple's element are (in order):

* interface: The network interface on which the service has been discovered
  (following the OS notation, eg: 'eth0')
* protocol: The type of IP protocol on which the service is published ('ipv4'
  or 'ipv6')
* name: The human-friendy name of the service as displayed by Bonjour browsing
  utilities
* stype: The service type following Bonjour's convention, eg '_http._tcp'
* domain: The domain on which the service was discovered, eg 'local'
* hostname: The hostname of the device publishing the service (eg: blabla.local)
* aprotocol: Unused
* ip_address The IP address of the device publishing the service (eg:
  '192.168.0.1' or 'fe80::1')
* port: The TCP or UDP port on which the service is running (eg: 80)
* txt: The TXT field associated with the service
