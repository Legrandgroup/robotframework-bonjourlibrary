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

* The first (optional) argument is the type of service (in the Bonjour 
terminology, the default value being `_http._tcp`)
* The second (optional) argument is the name of the network interface on which 
to browse for Bonjour devices (if not specified, search will be performed on 
all valid network interfaces)
* The third (optional) argument is the type of IP protocol to filter our (eg: 
`ipv6`, or `ipv4`, the default values being any IP version)
* If the fourth (optional) argument is set to True, we will also include the 
MAC address of devices in results (default value is to resolve IP addresses)

Return a list of services found on the network

Each entry of the list will contain a tuple describing a service. The tuple's 
element are (in order).

* interface: The network interface on which the service has been discovered
  (following the OS notation, eg: 'eth0')
* protocol: The type of IP protocol on which the service is published ('ipv4'
  or 'ipv6')
* name: The human-friendy name of the service as displayed by Bonjour browsing
  utilities
* stype: The service type following Bonjour's convention, eg '_http._tcp'
* domain: The domain on which the service was discovered, eg 'local'
* hostname: The hostname of the device publishing the service (eg: blabla.local)
* ip_address The IP address of the device publishing the service (eg:
  '192.168.0.1' or 'fe80::1')
* port: The TCP or UDP port on which the service is running (eg: 80)
* txt: The TXT field associated with the service

#### `Expect Service On IP`

*Test if at lease one service exists on a device with a specific IP address*

Note: the search will be performed on the service cache so `Get Services` or 
`Import Results` must have been run prior to calling this keyword

Also this means that this keyword will perform not perform the check for service
right now but rather at the time the last `Get Services` updated the internal
service cache.

To make sure you restrict to IPv4 or IPv6, filter IP types when running 
`Get Services`

#### `Expect No Service On IP`

*Test if a service is absent from a device with the specific IP address*

Note: the search will be performed on the service cache so `Get Services` or 
`Import Results` must have been run prior to calling this keyword

Also this means that this keyword will perform not perform the check for service
right now but rather at the time the last `Get Services` updated the internal
service cache.

To make sure you restrict to IPv4 or IPv6, filter IP types when running 
`Get Services`

#### `Wait For Service Name`

*Wait (until a timeout) for a service to be published (selection by name)*

* The first argument is the name of the service expected
* The second (optional) argument is the timeout for this service to be 
  published (if None, we will wait forever)
* The third (optional) argument is the type of service (in the Bonjour 
  terminology, the default value being `_http._tcp`)
* The forth (optional) argument is the name of the network interface on which 
  to browse for Bonjour devices (if not specified, search will be performed on 
  all valid network interfaces)
* The fifth (optional) argument is the type of IP protocol to filter our (eg: 
  `ipv6`, or `ipv4`, the default values being any IP version)
* If the sixth (optional) argument is set to True, we will also include the MAC 
  address of devices in results (default value is to resolve IP addresses)
        
Return the list of matching services found on the network (one entry per 
service, each service being described by tuples containing formatted like for 
keyword `Get Services`).

The return value can be stored and re-used later on to rework on this service 
list (see keyword `Import Results`)

If the service is already existing, this keyword will immediately return, 
otherwise, it will wait at most timeout (if provided) for the service to appear 
or will block forever (not recommended)

#### `Wait For No Service Name`

*Wait (until a timeout) for a service to stop being published (selection by 
name)*

If the service does not exist when running this keyword, it will immediately 
return, otherwise, it will wait at most timeout (if provided) for the service 
to be withdrawn or will block forever (not recommended)

After running this keyword, the internal database will be updated with the 
services remaining (filtered according to arguments (IPv4/IPv6, type etc...)

#### `Get All Services For IP`
  
*Filters results obtained by `Get Services` only returning entries for a 
specific IP address*

Note: this will have the side effect of changing the current database results 
from `Get Services` (used by other keywords)

#### `Get All Services For MAC`
  
*Filters results obtained by `Get Services` only returning entries for a 
specific MAC address... will obviously have MAC resolution on results*

Note: this will have the side effect of changing the current database results 
from `Get Services` (used by other keywords)

#### `Get IPv4 For MAC`

*Returns the IPv4 address of a Bonjour device matching MAC address*

Note: the search will be performed on the service cache so `Get Services` or 
`Import Results` must have been run prior to calling this keyword

Also this means that this keyword will perform not perform the check for service
right now but rather at the time the last `Get Services` updated the internal
service cache.

We can only search devices which did publish a Bonjour service that was in the 
filter of a call to `Get Services`
In order to use this keyword, you will need to request IP to MAC address 
resolution (6th argument of `Get Services`)

If there is more than one IPv4 address matching with the MAC address, an 
exception will be raised (unlikely except if there is an IP address update in 
the middle of `Get Services`)

#### `Get IPv6 For MAC`

*Returns the IPv6 address of a Bonjour device matching MAC address*

Note: the search will be performed on the service cache so `Get Services` or 
`Import Results` must have been run prior to calling this keyword

Also this means that this keyword will perform not perform the check for service
right now but rather at the time the last `Get Services` updated the internal
service cache.

We can only search devices which did publish a Bonjour service that was in the 
filter of a call to `Get Services`
In order to use this keyword, you will need to request IP to MAC address 
resolution (6th argument of `Get Services`)

If there is more than one IPv6 address matching with the MAC address, an 
exception will be raised (unlikely except if there is an IP address update in 
the middle of `Get Services`)

#### `Get IPv4 For Service Name`

*Get the IPv4 address for the device publishing a specific service*

Note: the search will be performed on the service cache so `Get Services` or 
`Import Results` must have been run prior to calling this keyword

Also this means that this keyword will perform not perform the check for service
right now but rather at the time the last `Get Services` updated the internal
service cache.

Return the IPv4 address or None if the service was not found.

If more than one service matches the requested service name, an exception will 
be raised

#### `Get IPv6 For Service Name`

*Get the IPv6 address for the device publishing a specific service*

Note: the search will be performed on the service cache so `Get Services` or 
`Import Results` must have been run prior to calling this keyword

Also this means that this keyword will perform not perform the check for service
right now but rather at the time the last `Get Services` updated the internal
service cache.

Return the IPv6 address or None if the service was not found.

If more than one service matches the requested service name, an exception will 
be raised

#### `Import Results`

*Import a service result list (previously returned by `Get Services` in order 
to work again/filter/extract from that list*

Will raise an exception of the list is not correctly formatted

### Robot Framework future keywords?

This lists keywords that might be implemented in the future if required:

* `Clear Results`
  
  *Empty a result cache as set by `Get Services` or `Import Results`*

* `Wait For Bonjour On IP`
  
  *Wait for a device to publish at least one service*

* `Wait For No Bonjour On IP`
  
  *Wait for a device to stop publish any service*

* `Wait For Bonjour On MAC`
  
  *Wait for a device to publish at least one service*

* `Wait For No Bonjour On MAC`
  
  *Wait for a device to stop publish any service*

* `Details For Service Name`
  
  *Get the whole service details (tuple) based on a service name (and 
  optionally a a host specified by either its MAC address of IP address)*

* `Details For Service Type`
  
  *Get the whole service details (tuple) based on a service type (and 
  optionally a port (recommended) and optionnally a host specified by either 
  its MAC address of IP address)*

