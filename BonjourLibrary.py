#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import division

import re
import sys
import time
import os

import subprocess

# The pythonic-version of arping below (using python scapy) is commented out because it cannot gain superuser rights via sudo, we should thus be root
# This would however be more platform-independent... instead, we run the arping command (via sudo) and parse its output
# import scapy.all
# def arping(iprange):
#     """Arping function takes IP Address or Network, returns nested mac/ip list"""
# 
#     scapy.all.conf.verb=0
#     ans,unans = scapy.all.srp(scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.all.ARP(pdst=iprange), timeout=2)
# 
#     collection = []
#     for snd, rcv in ans:
#         result = rcv.sprintf(r"%scapy.all.ARP.psrc% %scapy.all.Ether.src%").split()
#         collection.append(result)
#     return collection

"""Global variable required for function arping() below"""
arping_supports_r_i = True

def arping(ip_address, interface=None, use_sudo = True):
    """Run arping and returns a list of MAC addresses matching with the IP address provided in \p ip_address (or an empty list if there was no reply)
    
    \param ip_address The IP to probe
    \param interface A network interface on which to probe (or None if we should check all network interfaces)
    \param use_sudo Use sudo to run the arping command (set this to True if privilege elevation is required)
    
    \return A list of MAC addresses matching with \p ip_address. Beware that this can be empty or even contain more than one entry
    """
    
    global arping_supports_r_i
    
    if use_sudo:
        arping_cmd_prefix = ['sudo']
    else:
        arping_cmd_prefix = []
    
    arping_cmd_prefix += ['arping', '-c', '1']
    
    if arping_supports_r_i:
        arping_cmd = arping_cmd_prefix + ['-r']
        if not interface is None:
            arping_cmd += ['-i', str(interface)]
        arping_cmd += [str(ip_address)]
        proc = subprocess.Popen(arping_cmd, stdout=subprocess.PIPE, stderr=open(os.devnull, 'wb'))  # Hide stderr since we may expect errors if we use the wrong args (depending on the arping version we are using)
        result=[]
        for line in iter(proc.stdout.readline,''):
            result+=[line.rstrip()]

        exitvalue = proc.wait()
        if exitvalue == 0:
            return result
        else:
            arping_supports_r_i = False
    
    # Some versions of arping coming from the iproute package do not support -r and use -I instead of -i
    if not arping_supports_r_i:
        arping_cmd = arping_cmd_prefix  # Reset the command line that we started to build above
        if not interface is None:
            arping_cmd += ['-I', str(interface)]
        arping_cmd += [str(ip_address)]
        print(arping_cmd)
        proc = subprocess.Popen(arping_cmd, stdout=subprocess.PIPE)
        result=[]
        arping_header_regexp = re.compile(r'^ARPING')
        arp_reply_template1_regexp = re.compile(r'^.*from\s+([0-9]+\.[0-9]+\.[0-9]+.[0-9]+)\s+\[([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})\]')
        arp_reply_template2_regexp = re.compile(r'^.*from\s+([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})\s+[(]([0-9]+\.[0-9]+\.[0-9]+.[0-9]+)[)]')
        arping_ip_addr = None
        arping_mac_addr = None
        for line in iter(proc.stdout.readline,''):
            line = line.rstrip()
            if not re.match(arping_header_regexp, line):    # Skip the header from arping
                match = re.match(arp_reply_template1_regexp, line)
                if match:
                    arping_ip_addr = match.group(1)
                    arping_mac_addr = match.group(2)
                    break
                match = re.match(arp_reply_template2_regexp, line)
                if match:
                    arping_ip_addr = match.group(2)
                    arping_mac_addr = match.group(1)
                    break
            
        if not arping_mac_addr is None:
            result+=[arping_mac_addr]
        
        exitvalue = proc.wait()
        if exitvalue == 0:
            return result
        else:
            raise Exception('ArpingSubprocessFailed')

def mac_normalise(mac, unix_format=True):
    """\brief Convert many notation of a MAC address to to a uniform representation
    
    \param mac The MAC address as a string
    
    \param unix_format If set to true, use the UNIX representation, so would output: 01:23:45:67:89:ab
    
    Example: mac_normalise('01.23.45.67.89.ab') == mac_normalise('01:23:45:67:89:ab') == mac_normalise('01-23-45-67-89-ab') == mac_normalise('0123456789ab') == '0123456789ab'
    mac_normalise('01.23.45.67.89.ab') == '01:23:45:67:89:ab'
    """

    ret = ''
    mac = str(mac)
    mac = mac.lower()
    mac = mac.strip()
    re_mac_one = re.compile(r'^(\w{2})[:|\-](\w{2})[:|\-](\w{2})[:|\-](\w{2})[:|\-](\w{2})[:|\-](\w{2})$')
    re_mac_two = re.compile(r'^(\w{4})\.(\w{4})\.(\w{4})$')
    re_mac_three = re.compile(r'^(\w{12})$')
    one = re.match(re_mac_one, mac)
    two = re.match(re_mac_two, mac)
    tree = re.match(re_mac_three, mac)
    if one:
        select = one.groups()
    elif two:
        select = two.groups()
    elif tree:
        select = tree.groups()
    else:
        raise Exception('InvalidMACFormat:' + str(mac))
    if unix_format:
        delim=':'
    else:
        delim=''
    return delim.join(select)

class AvahiBrowseServiceEvent:
    
    """Class representing a service browse event (as output by avahi-browse)"""
    
    def __init__(self, entry_array):
        """\brief Class constructor
        
        \param entry_array One line of output as provided by avahi-browse in -p mode, formatted as a list of UTF-8 encoded strings
        
        This method will raise exceptions if the entry_array cannot be parsed correctly, otherwise the AvahiBrowseServiceEvent will be constructed properly.
        However, there are two cases where this AvahiBrowseServiceEvent is not fully populated:
        - if the event was an add ('-' prefix), we haven't resolved the service yet, so we will have minimal information (interface, ip_type, sname, stype, domain)
        - if the event contains a TXT field that spans over multiple lines, we will set self.txt_missing_end to True and the caller should fill-in the rest of the TXT record by calling our addline() method with each subsequent lines until self.txt_missing_end is set to False
        Note: self.txt_missing_end can also be queried by using our method called continued_on_next_line()
        
        The properties that are populated inside this class are:
        self.interface The network interface (following the OS notation, eg: 'eth0')
        self.ip_type The type of IP protocol on which the service is published ('ipv4' or 'ipv6')
        self.sname The service name as a string
        self.stype The service type following Bonjour's notation, eg '_http._tcp'
        self.domain The domain on which the services were discovered, eg 'local'
        self.event The type of avahi-browse event processed ('add' (+), 'update' (=) or 'del' (-))
        self.hostname The hostname of the device publishing the service (eg: blabla.local)
        self.ip_addr The IP address of the device publishing (eg: '192.168.0.1' or 'fe80::1')
        self.sport The service TCP or UDP port (eg: 80)
        self.txt The TXT field associated with the service
        self.txt_missing_end A boolean set to True if the TXT field is a multiline value and we need more lines to terminate it
        """
        
        if entry_array is None:
            raise Exception('InvalidEntry')
        type = entry_array[0]
        if type == '+' or type == '=':
            self._input = entry_array
            if ((type == '+' and len(entry_array) != 6) or (type == '=' and len(entry_array) != 10)):
                raise Exception('InvalidEntry')
            self.interface = entry_array[1]
            if entry_array[2] == 'IPv4':
                self.ip_type = 'ipv4'
            elif entry_array[2] == 'IPv6':
                self.ip_type = 'ipv6'
            else:
                raise Exception('InvalidIPType:' + entry_array[2])
            
            self.sname = AvahiBrowseServiceEvent.unescape_avahibrowse_string(entry_array[3])
            #self.sname = unicode(self.sname, 'utf-8')	# Not needed because avahi-browse already outputs UTF-8 text
            self.stype = AvahiBrowseServiceEvent.convert_to_raw_service_type(entry_array[4])
            self.domain = entry_array[5]
            if type == '=':	# '=' means resolved service so we get a bit more details on those lines
                self.hostname = entry_array[6]
                self.ip_addr = entry_array[7]
                self.sport = int(entry_array[8])
                self.txt = entry_array[9]
                #~ self.txt = unicode(self.txt, 'utf-8')	# Not needed because avahi-browse already outputs UTF-8 text
                self.txt_missing_end = not AvahiBrowseServiceEvent.isClosedString(self.txt)
                self.event = 'update'
            else:
                self.hostname = None
                self.ip_addr = None
                self.sport = None
                self.txt = None
                self.txt_missing_end = False
                self.event = 'add'
        else:
            raise Exception('UnknownType:' + type)
    
    def continued_on_next_line(self):
        """\brief Are there more lines required to fill-in this service description
        
        \return True if there are more lines required to fill-in this service description. In such case, the additional lines can be provided by subsequent calls to method add_line() below
        """
        return self.txt_missing_end
        
    def add_line(self, line):
        """\brief Provided additional lines to fill-in this service description
        
        \param line A new line to process, encoded as UTF-8 (without the terminating carriage return)
        """
        if not self.txt_missing_end:
            raise Exception('ExtraInputLine')
        else:
            #~ line = unicode(line, 'utf-8')	# Not needed because avahi-browse already outputs UTF-8 text
            self.txt += '\n' + line	# Re-insert the carriage return and continue the string
            self.txt_missing_end = not AvahiBrowseServiceEvent.isClosedString(self.txt)
    
    @staticmethod
    def unescape_avahibrowse_string(input):
        """\brief Unescape all escaped characters in string \p input
        
        \param input String to unescape
        
        \return The unescaped string (avahi-browse escaped bytes will lead to an UTF-8 encoded returned string)
        """
        output = ''
        espace_pos = input.find('\\')
        while espace_pos != -1:
            new_chunk = input[espace_pos+1:]
            output += input[:espace_pos]
            #print(output + '==>' + new_chunk)
            try:
                escaped_char = int(new_chunk[0]) * 100 + int(new_chunk[1]) * 10 + int(new_chunk[2])	# Fetch 3 following digits and convert them to a decimal value
                output += chr(escaped_char)	# Append escaped character to output (note: if escaped_char is not a byte (>255 for example), an exception will be raised here
                new_chunk = new_chunk[3:]	# Skip the 3 characters that make the escaped ASCII value
            except:
                output += '\\'	# This was not an escaped character... re-insert the '\'
            
            input = new_chunk
            espace_pos = input.find('\\')
        
        output += input
        return output
    
    @staticmethod
    def convert_to_raw_service_type(input):
        """\brief Convert an avahi-browse human readable service type string (eg 'Website') into the equivalent Bonjour-standard service type (eg '_http._tcp')
        
        \param input A string containing the human readable service type string as displayed by avahi-browse
        
        \return A string containing the equivalent Bonjour-standard service type
        """
        if input == 'Web Site':
            output = '_http._tcp'
        elif input == 'Workstation':
            output = '_workstation._tcp'
        elif input == 'VNC Remote Access':
            output = '_rfb._tcp.'
        elif input == 'Remote Disk Management':
            output = '_udisks-ssh._tcp.'
        elif input == 'Apple File Sharing':
            output = '_afpovertcp._tcp.'
        elif input == 'UNIX Printer':
            output = '_printer._tcp.'
        elif input == 'Internet Printer':
            output = '_ipp._tcp.'
        elif input == 'PDL Printer':
            output = '_pdl-datastream._tcp.'
        else:
            output = input
        return output
        
    @staticmethod
    def isClosedString(string):
        """\brief Checks if \p string is complete (not continuing on another line)
        
        \param string The input string to check
        
        \return True if the string is complete and does not need a closing quote
        """
        closedString = True
        if len(string)>=1:	# There is at least one character
            if string.startswith('"'):	# First character is a quote
                closedString = string.endswith('"')
        return closedString
    
    def __repr__(self):
        if self.event == 'add':
            output = '+'
        elif self.event == 'update':
            output = '!'
        elif self.event == 'del':
            output = '-'
        else:
            output = '?'
        output += '[if=' + str(self.interface) + ']: "' + str(self.sname) + '"'
        if self.ip_addr:
            output += ' '+ str(self.ip_addr)
        if self.hostname:
            output += '(' + str(self.hostname)
        if self.sport:
            output += ':' + str(self.sport)
        if self.hostname:
            output += ')'
        if self.txt:
            output += ' TXT=[' + self.txt
            if self.continued_on_next_line():
                output += '(misssing end)'
            output += ']'
        return output

class BonjourService:
    """Description of a Bonjour service (this is a data container without any method (the equivalent of a C-struct))"""
    
    def __init__(self, hostname, aprotocol, ip_address, port, txt, flags, mac_address = None):
        self.hostname = hostname
        self.aprotocol = aprotocol
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.port = port
        self.txt = txt
        self.flags = flags
        
    def __repr__(self):
        result = '[' + str(self.hostname)
        if not self.port is None:
            result += ':' + str(self.port)
        result += ',IP=' + str(self.ip_address)
        if not self.mac_address is None:
            result += '(' + str(self.mac_address) + ')'
        if self.txt:
            result += ',TXT=[' + str(txt) + ']'
        result += ']'
        return result


class BonjourServiceDatabase:
    """Bonjour service database"""
    
    def __init__(self, resolve_mac = False):
        """Initialise an empty BonjourServiceDatabase
        
        \param resolve_mac If True, we will also resolve each entry to store the MAC address of the device together with its IP address
        """
        self._database = {}
        self.resolve_mac = resolve_mac

    def __repr__(self):
        temp = ''

        try:
            values = self._database.iteritems()
        except AttributeError:
            values = self._database.items()

        for (key, value) in values:
            temp += '''key:%s
value:%s
''' % (key, value)
        return temp

    def add(self, key, bonjour_service):
        """Add one Bonjour service in database
        
        \param key A tuple containing the description of the Bonjour service (interface, protocol, name, stype, domain) (note that interface is a string containing the interface name following the OS designation)
        \param bonjour_service An instance of BonjourService to add in the database for this \p key
        """

        (interface_osname, protocol, name, stype, domain) = key
        if self.resolve_mac and not bonjour_service is None:
            mac_address_list = arping(bonjour_service.ip_address, interface=interface_osname, use_sudo=True)
            if len(mac_address_list) == 0:
                bonjour_service.mac_address = None
            else:
                if len(mac_address_list) > 1:  # More than one MAC address... issue a warning
                    logger.warning('Got more than one MAC address for IP address ' + str(bonjour_service.ip_address) + ': ' + str(mac_address_list) + '. Using first')
                bonjour_service.mac_address = mac_address_list[0]
        self._database[key] = bonjour_service

    def remove(self, key):
        """Remove one Bonjour service in database
        
        \param key A tuple containing (interface, protocol, name, stype, domain), which is the key of the record to delete from the database 
        """

        if key in self._database.keys():
            del self._database[key]

    def reset(self):
        """\brief Empty the database"""
        self._database = {}
        
    def processEvent(self, avahi_event):
        """\brief Update this database according to the \p avahi_event
        
        \param avahi_event The event to process, provided as an instance of AvahiBrowseServiceEvent
        """
        key = (avahi_event.interface, avahi_event.ip_type, avahi_event.sname, avahi_event.stype, avahi_event.domain)
        if avahi_event.event == 'add':
            # With add events, we don't have any information about the service yet (it is not resolved)
            self.add(key, None)
        elif avahi_event.event == 'update':
            bonjour_service = BonjourService(avahi_event.hostname, None, avahi_event.ip_addr, avahi_event.sport, avahi_event.txt, 0, mac_address = None)
            self.add(key, bonjour_service)
        else:
            raise Exception('UnknownEvent')
        
    def export_to_tuple_list(self):
        """Export this database to a list of tuples (so that it can be processed by RobotFramework keywords)
        
        \return A list of tuples containing (interface, protocol, name, stype, domain, hostname, aprotocol, ip_address, sport, txt, flags, mac_address) 
        """
        export = []
        try:
            records = self._database.iteritems()
        except AttributeError:
            records = self._database.items()
        
        for (key, bonjour_service) in records:
            (interface_osname, protocol, name, stype, domain) = key
            hostname = bonjour_service.hostname
            aprotocol = bonjour_service.aprotocol
            ip_address = bonjour_service.ip_address
            port = bonjour_service.port
            txt = bonjour_service.txt
            flags = bonjour_service.flags
            mac_address = bonjour_service.mac_address
            export += [(interface_osname, protocol, name, stype, domain, hostname, aprotocol, ip_address, port, txt, flags, mac_address)]
        
        return export
        

    def is_ip_address_in_db(self, ip_address):
        try:
            records = self._database.iteritems()
        except AttributeError:
            records = self._database.items()
        
        for (key, bonjour_service) in records:
            if bonjour_service.ip_address == ip_address:
                return True
        return False

    def is_mac_address_in_db(self, mac_address):
        if mac_address is None:
            return False
        
        try:
            records = self._database.iteritems()
        except AttributeError:
            records = self._database.items()
        
        for (key, bonjour_service) in records:
            if bonjour_service.mac_address == mac_address:
                return True
        return False
        
    def get_ip_address_from_mac_address(self, searched_mac):
        """\brief Check the IP address of a Bonjour device, given its MAC address
        
        Note: the database must have been filled with a list of devices prior to calling this method
        
        \param searched_mac The MAC address of the device to search
        
        \return The IP address of the device (if found)
        """

        searched_mac = mac_normalise(searched_mac, False)
        for key in self._database.keys():
            mac_product = self._database[key].mac_address
            if not mac_product is None:
                mac_product = mac_normalise(mac_product, False)
                if searched_mac == mac_product:
                    ip_address = self._database[key].ip_address
                    return ip_address

class BonjourLibrary:
    """Robot Framework Bonjour Library"""

    ROBOT_LIBRARY_DOC_FORMAT = 'ROBOT'
    ROBOT_LIBRARY_SCOPE = 'GLOBAL'
    ROBOT_LIBRARY_VERSION = '1.0'

    def __init__(self, domain='local', avahi_browse_exec_path=None):
        self._domain = domain
        self.service_database = None
        self._avahi_browse_exec_path = avahi_browse_exec_path

    def start(self):#Lionel: remove this keyword
        """Connects to the Avahi service.

        Example:
        | Start |
        """

        #ToolLibrary.run(self._avahi_daemon_exec_path, 'restart')
        self.service_database = BonjourServiceDatabase()

    def stop(self):#Lionel: remove this keyword
        """Disconnects from the Avahi service.

        Example:
        | Stop |
        """

        self.service_database = None

    def get_services(self, service_type = '_http._tcp', interface_name = None):
        """Get all currently published Bonjour services as a list
        
        First (optional) argument `service_type` is the type of service (in the Bonjour terminology, the default value being `_http._tcp`)
        Second (optional) argument `interface_name` is the name of the network interface on which to browse for Bonjour devices (if not specified, search will be performed on all valid network interfaces)
        
        Return a list of services found on the network (one entry per service, each service being described by a tuple containing (interface_osname, protocol, name, stype, domain, hostname, aprotocol, ip_address, port, txt, flags, mac_address) 
        
        Example:
        | Get Services | _http._tcp |
        =>
        | ${list} |
        
        | Get Services | eth1 | _http._tcp |
        =>
        | ${list} |
        """
        
        stype = ''
        
        if service_type and service_type != '*':
            service_type_arg = service_type
        else:
            service_type_arg = '-a'

        p = subprocess.Popen(['avahi-browse', '-p', '-r', '-l', '-t', service_type_arg], stdout=subprocess.PIPE)

        previous_line_continued = False
        for line in p.stdout:
            line = line.rstrip('\n')
            if previous_line_continued:
                avahi_event.add_line(line)
            else:
                avahi_event = AvahiBrowseServiceEvent(line.split(';'))
            previous_line_continued = avahi_event.continued_on_next_line()
            if not previous_line_continued:
                print('Getting event ' + str(avahi_event))
                if interface_name is None or avahi_event.interface == interface_name:   # Only take into account services on the requested interface (if an interface was provided)
                    self.service_database.processEvent(avahi_event)
        
        logger.debug('Services found: ' + str(self.service_database))
        return self.service_database.export_to_tuple_list()

    def expect_service_on_ip(self, ip_address):
        """Test if service type `service_type` is running on device with IP address `ip_address`
        
        Note: `Browse Services` must have been run prior to calling this keyword
        
        Example:
        | Expect Service On IP | 192.168.0.1 |
        """

        if not self.service_database.is_ip_address_in_db(ip_address):
            raise Exception('ServiceNotFoundOn:' + str(ip_address))

    def expect_no_service_on_ip(self, ip_address):
        """Test if service type `service_type` is running on device with IP address `ip_address`
        
        Note: `Browse Services` must have been run prior to calling this keyword
        
        Example:
        | Expect No Service On IP | 192.168.0.1 |
        """

        if self.service_database.is_ip_address_in_db(ip_address):
            raise Exception('ServiceExistsOn:' + str(ip_address))
    
    def get_ip(self, mac):
        """Returns the IP address matching MAC address mac from the list a Bonjour devices in the database
        
        Note: `Browse Services` must have been run prior to calling this keyword
        
        Example:
        | Get IP | 00:04:74:12:00:01 |
        =>
        | 169.254.47.26 |
        """

        temp = self.service_database.get_ip_address_from_mac_address(mac)
        if temp is not None:
            ret = temp
        else:
            raise Exception("MachineNotFound:" + str(mac))
        ret = unicode(ret)
        return ret

    def get_ip_for_name(self, key):
        """Get Application Point name from `key`.
        
        Note: `Browse Services` must be called before calling this keyword
        
        Return IP.
        
        Example:
        | ${data} = | Check Run | ip | _http._tcp |
        | Get APName | ${data} |
        =>
        | ${apname} |
        """

        ret = self.service_database.get_info_from_key(key)[0]
        ret = unicode(ret)
        return ret

if __name__ == '__main__':
    try:
        from console_logger import LOGGER as logger
    except ImportError:
        import logging

        logger = logging.getLogger('console_logger')
        logger.setLevel(logging.DEBUG)
        
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logger.addHandler(handler)

    try:
        input = raw_input
    except NameError:
        pass

    MAC = '00:04:74:12:00:00'
    IP = '169.254.5.18'
    #print('Arping result: ' + str(arping(ip_address='10.10.8.1', interface='eth0', use_sudo=True)))
    AVAHI_BROWSER = 'avahi-browse'
    BL = BonjourLibrary('local', AVAHI_BROWSER)
    BL.start()
    BL.stop()
    BL.start()
    input('Press enter & "Enable UPnP/Bonjour" on web interface')
    BL.get_services(service_type='_http._tcp', interface_name='eth1')
    BL.expect_service_on_ip(IP)
    input('Press enter & "Disable UPnP/Bonjour" on web interface')
    BL.expect_no_service_on_ip(IP)
else:
    from robot.api import logger

