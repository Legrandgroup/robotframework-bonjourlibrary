BonjourLibrary for Robot Framework
==================================


## Introduction

BonjourLibrary is a [Robot Framework](http://robotframework.org) test
library for testing devices announcing services using the Bonjour/mDNS protocol.
It will browse the Bonjour services on the network and allow Robot Framework to
use all information provided by the Bonjour/mDNS protocol via Robot Framework
keywords.

This library currently only works for Linux platforms.

In order to browse Bonjour devices, you will need to have avahi daemon running
on the machine where the library is running.

BonjourLibrary is open source software licensed under
[Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0.html).

## For users

### Installation

### Robot Framework keywords

The following RobotFramework keywords are made available by this library:
Note: it is advised to go directly inside the python code's docstrings (or via
RIDE's online help) to get a detailed description of keywords).

#### `Start`

*Start the Bonjour/mDNS browsing session*

#### `Stop`
*Stop the Bonjour/mDNS browsing session*


## For developpers

### Architecture of BonjourLibrary

WIP

### D-Bus messaging used between `BonjourLibrary` and `avahi-daemon`

WIP