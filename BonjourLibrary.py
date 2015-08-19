#!/usr/bin/python
# -*- coding: utf-8 -*-

""" Legrand MP5B """

from __future__ import division

import re
import sys
import time

import threading

import gobject
import dbus
import dbus.mainloop.glib

import subprocess

import avahi
import avahi.ServiceTypeDatabase

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

def arping(ip_address, interface=None, use_sudo = True):
    """
    This function runs arping and returns a list of MAC addresses matching with the IP address provided as argument (or an empty list if there was no reply)
    """
    if use_sudo:
        arping_cmd = ['sudo']
    else:
        arping_cmd = []
    arping_cmd += ['arping', '-c', '1', '-r']
    if not interface is None:
        arping_cmd += ['-i', str(interface)]
    arping_cmd += [str(ip_address)]
    proc = subprocess.Popen(arping_cmd, stdout=subprocess.PIPE)
    result=[]
    for line in iter(proc.stdout.readline,''):
        result+=[line.rstrip()]

    return result

def mac_normalise(mac, unix_format=True):
    """ Convert all friendly `mac` string to a uniform representation.

    Example:
    | MAC String | 01.23.45.67.89.ab |
    | MAC String | 01:23:45:67:89:ab |
    | MAC String | 01-23-45-67-89-ab |
    | MAC String | 012345.6789ab |
    | MAC String | 0123456789ab |
    =>
    | 0123456789ab |
    
    \param unix_format If set to true, use the UNIX representation, so would output: 01:23:45:67:89:ab
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
    return unicode(delim.join(select))

class BonjourService:
    """ Description of a Bonjour service (this is a data container without any method (the equivalent of a C-struct))
    """
    
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
            result += ',TXT="' + str(txt) + '"'
        result += ']'
        return result


class BonjourServiceDatabase:

    """ Bonjour service database"""

    def __init__(self, resolve_mac = False):
        """
        Initialise an empty BonjourServiceDatabase
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
        """ Add one Bonjour service in database
        
        \param key A tuple containing the description of the Bonjour service (interface, protocol, name, stype, domain) (note that interface is a string containing the interface name following the OS designation)
        \param bonjour_service An instance of BonjourService to add in the database for this \p key
        """

        (interface_osname, protocol, name, stype, domain) = key
        if self.resolve_mac:
            bonjour_service.mac_address = arping(bonjour_service.ip_address, interface=interface_osname, use_sudo=True)
        if key not in self._database.keys():
            print('Adding entry for key ' + str(key))
            self._database[key] = bonjour_service

    def remove(self, key):
        """ Remove one Bonjour service in database
        
        \param key A tuple containing (interface, protocol, name, stype, domain), which is the key of the record to delete from the database 
        """

        if key in self._database.keys():
            del self._database[key]

    def reset(self):
        """ reset Bonjour service in database """

        self._database = {}

    def get_address_from_mac(self, mac):
        """ Get the details of the services published for the host matching with MAC address \p mac
        \param mac The MAC address of the device to search
        
        \return The IP address of the device (if found)
        """

        print('Entering get_address_from_mac()')
        mac = mac_normalise(mac, False)
        mac_manufacturer = mac[10:]
        for key in self._database.keys():
            print('Got entry with key' + str(key))
            mac_product = self._database[key].mac_address
            print('Searching in db... found MAC="' + str(mac_product) + '"')
            if not mac_product is None:
                bonjour_mac = mac_normalise(mac_manufacturer + mac_product, False)
                if mac == bonjour_mac:
                    ip_address = self._database[key].ip_address
                    return ip_address

    def get_key_from_address(self, address):
        """ get the first service with given IP address in database """

        try:
            values = self._database.iteritems()
        except AttributeError:
            values = self._database.items()

        for (key, value) in values:
            if address == value[2]:
                return key


class AvahiBrowser:
    
    def __init__(self, bus, dbus_iface, service_type, finished_event = None, domain = 'local'):
        self.bus = bus
        self.dbus_iface = dbus_iface
        self.service_type = service_type
        self.domain = domain
        self.finished_event = finished_event
        self.service_database = BonjourServiceDatabase(resolve_mac = True)
        
        logger.debug('Starting a new service browser on domain=' + str(self.domain) + ', service type=' + str(self.service_type))
        browser_path = self.dbus_iface.ServiceBrowserNew(avahi.IF_UNSPEC, avahi.PROTO_UNSPEC, self.service_type, self.domain, dbus.UInt32(0))
        browser_proxy = self.bus.get_object(avahi.DBUS_NAME, browser_path)
        browser_interface = dbus.Interface(browser_proxy, avahi.DBUS_INTERFACE_SERVICE_BROWSER)
        browser_interface.connect_to_signal('AllForNow', self._serviceBrowserDone)
        browser_interface.connect_to_signal('CacheExhausted', self._serviceBrowserCache)
        browser_interface.connect_to_signal('Failure', self._serviceBrowserFailure)
        browser_interface.connect_to_signal('Free', self._serviceBrowserFree)
        browser_interface.connect_to_signal('ItemNew', self._serviceBrowserItemAdded)
        browser_interface.connect_to_signal('ItemRemove', self._serviceBrowserItemRemoved)

    def _serviceBrowserItemAdded(
        self,
        interface,
        protocol,
        name,
        stype,
        domain,
        flags,
        ):
        """ add a Bonjour service in database """

        logger.debug('Avahi:ItemNew')
        (
            interface,
            protocol,
            name,
            stype,
            domain,
            host,
            aprotocol,
            address,
            port,
            txt,
            flags
        ) = self.dbus_iface.ResolveService(
            interface,
            protocol,
            name,
            stype,
            domain,
            avahi.PROTO_UNSPEC,
            dbus.UInt32(0),
            )
        interface_osname = self.dbus_iface.GetNetworkInterfaceNameByIndex(interface)
        key = (interface_osname, protocol, name, stype, domain)
        self.service_database.add(key, BonjourService(host, aprotocol, address, port, avahi.txt_array_to_string_array(txt), flags, mac_address=None))

    def _serviceBrowserItemRemoved(
        self,
        interface,
        protocol,
        name,
        stype,
        domain,
        flags,
        ):
        """ remove a Bonjour service in database """

        logger.debug('Avahi:ItemRemove')
        interface_osname = self.dbus_iface.GetNetworkInterfaceNameByIndex(interface)
        key = (interface_osname, protocol, name, stype, domain)
        self.service_database.remove(key)

    def _serviceBrowserDone(self):
        """ no more Bonjour service """

        logger.debug('Avahi:AllForNow')
        if not self.finished_event is None:
            self.finished_event.set()

    def _serviceBrowserFailure(self, error):
        """ avahi failure """

        logger.debug('Avahi:Failure')
        logger.warn('Error %s' % error)
        if not self.finished_event is None:
            self.finished_event.set()

    @staticmethod
    def _serviceBrowserFree():
        """ free """

        logger.debug('Avahi:Free')

    @staticmethod
    def _serviceBrowserCache():
        """ cache """

        logger.debug('Avahi:CacheExhausted')
        
    def get_service_database(self):
        return self.service_database


class AvahiWrapper:

    """ Bonjour service base on http://avahi.org/ """

    POLL_WAIT = 1 / 100

    def __init__(self, domain):
        """ DBus connection """

        self._domain = domain
        self._dbus_loop = gobject.MainLoop()
        self._bus = dbus.SystemBus(private=True)
        
        wait_bus_owner_timeout = 5  # Wait for 5s to have an owner for the bus name we are expecting
        logger.debug('Going to wait for an owner on bus name ' + avahi.DBUS_NAME)
        while not self._bus.name_has_owner(avahi.DBUS_NAME):
            time.sleep(0.2)
            wait_bus_owner_timeout -= 0.2
            if wait_bus_owner_timeout <= 0: # We timeout without having an owner for the expected bus name
                raise Exception('No owner found for bus name ' + avahi.DBUS_NAME)
         
        logger.debug('Got an owner for bus name ' + avahi.DBUS_NAME)
        gobject.threads_init()    # Allow the mainloop to run as an independent thread
        dbus.mainloop.glib.threads_init()
        
        self.service_database = BonjourServiceDatabase()
        
        dbus_object_name = avahi.DBUS_PATH_SERVER
        logger.debug('Going to communicate with object ' + dbus_object_name)

        self._avahi_proxy = self._bus.get_object(avahi.DBUS_NAME, dbus_object_name)   # Required to attach to signals
        self._dbus_iface = dbus.Interface(self._avahi_proxy, avahi.DBUS_INTERFACE_SERVER) # Required to invoke methods
        
        logger.debug("Connected to D-Bus")
        self._dbus_loop_exit = threading.Event() # Create a new threading event that will ask the D-Bus background thread to exit
        self._dbus_loop_exit.clear()

        self._dbus_loop_continue = threading.Event() # Create a new threading event that will ask the D-Bus background thread to resume running after having been paused using 
        self._dbus_loop_continue.clear()
        
        self._dbus_loop_thread = threading.Thread(target = self._loopHandleDbus)    # Start handling D-Bus messages in a background thread
        self._dbus_loop_thread.setDaemon(True)    # D-Bus loop should be forced to terminate when main program exits
        self._dbus_loop_thread.start()
        
        self._bus.watch_name_owner(avahi.DBUS_NAME, self._handleBusOwnerChanged) # Install a callback to run when the bus owner changes
        
        self._remote_version = ''
        self._getversion_unlock_event = threading.Event() # Create a new threading event that will allow the GetVersionString() D-Bus call below to execute within a timed limit
        
        self._dbus_service_browser_lock = threading.Lock () # Lock that makes sure only one service browser exists at any specific time
        self._dbus_service_browser_finished = threading.Event() # Threading event used to notify that all Bonjour services have been parsed by a service browser

        self._getversion_unlock_event.clear()
        self._dbus_iface.GetVersionString(reply_handler = self._getVersionUnlock, error_handler = self._getVersionError)
        if not self._getversion_unlock_event.wait(4):   # We give 4s for slave to answer the GetVersion() request
            raise Exception('TimeoutOnGetVersion')
        else:
            logger.debug('avahi version: ' + self._remote_version)
        
        self._getstate_unlock_event = threading.Event() # Create a new threading event that will allow the GetState() D-Bus call below to execute within a timed limit 

        self._getstate_unlock_event.clear()
        self._dbus_iface.GetState(reply_handler = self._getStateUnlock, error_handler = self._getStateError)
        if not self._getstate_unlock_event.wait(4):   # We give an additional 4s for slave to answer the GetState() request
            raise Exception('TimeoutOnAvahiState')

        self.reset()

        
    def reset(self):
        """
        Reset the internal database of leases by sending a SIGHUP to dnsmasq
        """
        
        pass    #self._lease_database.reset()   # Empty internal database
        
    def exit(self):
        """
        Terminate the D-Bus handlers and the D-Bus loop
        """
        if self._dbus_iface is None:
            raise Exception('Method invoked on non existing D-Bus interface')
        # Stop the dbus loop
        self.stopDBusLoop()
        
    # D-Bus-related methods
    def stopDBusLoop(self):
        """
        Terminate the D-Bus handlers and the D-Bus loop
        """
        # Notify the background thread that the mainloop should not be resumed
        self._dbus_loop_exit.set()
        self.pauseDBusLoop()
        
        self._dbus_loop = None
    
    def pauseDBusLoop(self):
        if not self._dbus_loop is None:
            self._dbus_loop.quit()
            
    def resumeDBusLoop(self):
        if not self._dbus_loop is None:
            self._dbus_loop_continue.set()
    
    # D-Bus-related methods
    def _loopHandleDbus(self):
        """
        This method should be run within a thread... This thread's aim is to run the Glib's main loop while the main thread does other actions in the meantime
        This methods will loop infinitely to receive and send D-Bus messages and will only stop looping when the value of self._loopDbus is set to False (or when the Glib's main loop is stopped using .quit()) 
        """
        logger.debug("Starting dbus mainloop")
        while not self._dbus_loop_exit.isSet(): # If _dbus_loop_exit is set, we will just stop finish this background thread
            self._dbus_loop.run()
            # Our mainloop has been interrupted by an external source... check if we should exit
            if not self._dbus_loop_exit.isSet():
                # We should not exit, wait until someone instructs us to resume the main loop (using the _dbus_loop_continue event)
                self._dbus_loop_continue.wait()
                self._dbus_loop_continue.clear()    # Clear this flag for next interruption
            
        logger.debug("Stopping dbus mainloop")

    def _handleBusOwnerChanged(self, new_owner):
        """
        Callback called when our D-Bus bus owner changes 
        """
        if new_owner == '':
            logger.warn('No owner anymore for bus name ' + avahi.DBUS_NAME)
            raise Exception('LostAvahiDaemon')
        else:
            pass # Owner exists

    def _getVersionUnlock(self, return_value):
        """
        This method is used as a callback for asynchronous D-Bus method call to GetVersionString()
        It is run as a reply_handler to unlock the wait() on _getversion_unlock_event
        """
        #logger.debug('_getVersionUnlock() called')
        self._remote_version = str(return_value)
        self._getversion_unlock_event.set() # Unlock the wait() on self._getversion_unlock_event
        
    def _getVersionError(self, remote_exception):
        """
        This method is used as a callback for asynchronous D-Bus method call to GetVersion()
        It is run as an error_handler to raise an exception when the call to GetVersion() failed
        """
        logger.error('Error on invocation of GetVersionString() to avahi daemon, via D-Bus')
        raise Exception('ErrorOnDBusGetVersion')

    def _getStateUnlock(self, return_value):
        """
        This method is used as a callback for asynchronous D-Bus method call to GetState()
        It is run as a reply_handler to unlock the wait() on _getstate_unlock_event
        """
        #logger.debug('_getStateUnlock() called')
        if (return_value == 2): # AVAHI_CLIENT_NO_FAIL
            self._getstate_unlock_event.set() # Unlock the wait() on self._getstate_unlock_event
        else:
            self._getStateError(remote_exception = Exception('GetState returned value ' + str(return_value)))
        
    def _getStateError(self, remote_exception):
        """
        This method is used as a callback for asynchronous D-Bus method call to GetVersion()
        It is run as an error_handler to raise an exception when the call to GetVersion() failed
        """
        logger.error('Error on invocation of GetState() to avahi daemon, via D-Bus')
        raise Exception('ErrorOnDBusGetState')


    def _wait_daemon(self, timeout=10):
        """ wait daemon available """

        maxtime = time.time() + int(timeout)
        while True:
            time.sleep(AvahiWrapper.POLL_WAIT)
            if time.time() > maxtime:
                logger.warn('Avahi dameon not available')
                break
            if self.get_state() == 2:  # AVAHI_CLIENT_NO_FAIL
                logger.debug('Avahi daemon available')
                break

    def get_version(self):
        """ get version """

        return self._remote_version

    def get_interface_name(self, interface_index):
        """ get interface name from index """

        return self._dbus_iface.GetNetworkInterfaceNameByIndex(interface_index)

    def get_state(self):
        """ get state """

        return self._dbus_iface.GetState()

    def browse_service_type(self, stype):
        """ browse service """

        if self._dbus_iface is None:
            raise Exception('You need to connect before getting interface name')
        try:
            with self._dbus_service_browser_lock:
                self.pauseDBusLoop()    # We must pause the D-Bus background thread or we may miss the first results from the ServiceBrowser created below (because callbacks for signals are not yet in place)
                self._dbus_service_browser_finished.clear()
                
                browser = AvahiBrowser(bus = self._bus, dbus_iface = self._dbus_iface, service_type = stype, finished_event = self._dbus_service_browser_finished)
                
                self.resumeDBusLoop()   # Now we are ready to process signals, resume the D-Bus background thread
                self._dbus_service_browser_finished.wait(30)    # Give at most 30s to get all Bonjour devices
                self.service_database = browser.get_service_database()
                
        except:
            raise Exception("DBus exception occurs in browse_service_type with type '%s' and value '%s'" % sys.exc_info()[:2])



class BonjourWrapper(AvahiWrapper):

    """ specialization class """

    pass


class BonjourLibrary:

    """ Robot Framework Bonjour Library """

    ROBOT_LIBRARY_DOC_FORMAT = 'ROBOT'
    ROBOT_LIBRARY_SCOPE = 'GLOBAL'
    ROBOT_LIBRARY_VERSION = '1.0'

    def __init__(self, domain='local', avahi_daemon_exec_path=None):
        self._domain = domain
        self._avahi_daemon_exec_path = avahi_daemon_exec_path
        self._browser = None

    def _browse_generic(self, stype):
        """ connect to DBus, reset database and browse service """
 
        self._browser.service_database.reset()
        self._browser.browse_service_type(stype)
        logger.debug('DBus loop ending with database:%s' % self._browser.service_database)

    def start(self):
        """ Start monitoring the Avahi service.

        Example:
        | Start |
        """

        #ToolLibrary.run(self._avahi_daemon_exec_path, 'restart')
        self._browser = BonjourWrapper(self._domain)

    def stop(self):
        """ Stop monitoring the Avahi service.

        Example:
        | Stop |
        """

        self._browser.exit()
        self._browser = None
        #ToolLibrary.run(self._avahi_daemon_exec_path, 'stop')

    def check_run(self, address, stype='_http._tcp'):
        """ Test if service type `stype` is present on `address`.
        
        Return service.
        
        Example:
        | Check Run | ip | _http._tcp |
        =>
        | ${service} |
        """

        self._browse_generic(stype)
        temp = self._browser.service_database.get_key_from_address(address)
        if temp is not None:
            ret = temp
        else:
            raise LegrandError("Service '%s' expected on '%s'" % (stype, address))
        return ret

    def check_stop(self, address, stype='_http._tcp'):
        """ Test if service type `stype` is missing on `address`.
        
        Return service.
        
        Example:
        | Check Stop | ip | _http._tcp |
        """

        self._browse_generic(stype)
        temp = self._browser.service_database.get_key_from_address(address)
        if temp is not None:
            raise LegrandError("Service '%s' not expected on '%s'" % (stype, address))

    def get_ip(self, mac, stype='_http._tcp'):
        """ Get first ip address which have service type `stype` and `mac`.
        
        Return IP.
        
        Example:
        | Get IP | 01.23.45.67.89.ab | _http._tcp |
        =>
        | ip |
        """

        self._browse_generic(stype)
        temp = self._browser.service_database.get_address_from_mac(mac)
        if temp is not None:
            ret = temp
        else:
            raise Exception("Service '%s' expected on '%s'" % (stype, mac))
        ret = unicode(ret)
        return ret

    def get_apname(self, key):
        """ Get Application Point name from `key`.
        
        Return IP.
        
        Example:
        | ${data} = | Check Run | ip | _http._tcp |
        | Get APName | ${data} |
        =>
        | ${apname} |
        """

        ret = self._browser.service_database.get_info_from_key(key)[0]
        ret = unicode(ret)
        return ret

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)    # Use Glib's mainloop as the default loop for all subsequent code

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

    MAC = '00:04:74:05:00:f0'
    IP = '10.10.8.39'
    AVAHI_DAEMON = '/etc/init.d/avahi-daemon'
    BL = BonjourLibrary('local', AVAHI_DAEMON)
    BL.start()
    BL.stop()
    BL.start()
    input('Press enter & "Enable UPnP/Bonjour" on web interface')
    assert IP == BL.get_ip(MAC, '_http._tcp')
    DATA = BL.check_run(IP, '_http._tcp')
    BL.get_apname(DATA)
    input('Press enter & "Disable UPnP/Bonjour" on web interface')
    BL.check_stop(IP, '_http._tcp')
else:
    from robot.api import logger

