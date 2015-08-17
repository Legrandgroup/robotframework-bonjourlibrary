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

import avahi
import avahi.ServiceTypeDatabase

#from ToolLibrary import ToolLibrary

class ServiceDatabase:

    """ Bonjour service database"""

    HOST_LINDY = r'^AP-{1}(.*)-{1}(.*)\.{1}(.*)$'
    HOST_MP5 = r'^(SwitchFTTO)(.*)\.{1}(.*)$'

    def __init__(self):
        self._database = {}

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

    def add(self, arg):
        """ add Bonjour service in database """

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
            flags,
            ) = arg
        key = (interface, protocol, name, stype, domain)
        value = (
            host,
            aprotocol,
            address,
            port,
            avahi.txt_array_to_string_array(txt),
            flags,
            )
        if key not in self._database.keys():
            self._database[key] = value

    def remove(self, key):
        """ remove Bonjour service in database """

        if key in self._database.keys():
            del self._database[key]

    def reset(self):
        """ reset Bonjour service in database """

        self._database = {}

    def get_address_from_mac(self, mac):
        """ get the first IP address with MAC in hostname """

        #mac = ToolLibrary.mac_string(mac)
        #mac_manufacturer = ToolLibrary.mac_manufacturer(mac)
        for key in self._database.keys():
            print('Got entry with key' + str(key))
            temp = self.get_info_from_key(key)
            if temp is not None:
                mac_product = temp[1]
                print('Searching in db... found MAC="' + mac_product + '"')
                #bonjour_mac = ToolLibrary.mac_string(mac_manufacturer + mac_product)
                if mac == bonjour_mac:
                    address = self._database[key][2]
                    return address

    def get_key_from_address(self, address):
        """ get the first service with given IP address in database """

        try:
            values = self._database.iteritems()
        except AttributeError:
            values = self._database.items()

        for (key, value) in values:
            if address == value[2]:
                return key

    def get_info_from_key(self, key):
        """ get information from key """

        host = self._database[key][0]
        result = re.match(ServiceDatabase.HOST_LINDY, host)
        if result is not None:
            (apname, mac_product, where) = result.groups()
            return [apname, mac_product, where]
        result = re.match(ServiceDatabase.HOST_MP5, host)
        if result is not None:
            (apname, mac_product, where) = result.groups()
            mac_product = '0d9cf0'  # FIXME
            return [apname, mac_product, where]


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
        
        self.service_database = ServiceDatabase()
        
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
            logger.warn('No owner anymore for bus name ' + DnsmasqDhcpServerWrapper.DNSMASQ_DBUS_NAME)
            raise Exception('LostDhcpSlave')
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

        return _remote_version

    def get_interface_name(self, interface_index):
        """ get interface name from index """

        if self._dbus_iface is None:
            raise LegrandError('You need to connect before getting interface name')
        else:
            interface_name = self._dbus_iface.GetNetworkInterfaceNameByIndex(interface_index)
            return interface_name

    def get_state(self):
        """ get state """

        if self._dbus_iface is None:
            raise LegrandError('You need to connect before getting interface name')
        else:
            state = self._dbus_iface.GetState()
            return state

    def browse_service_type(self, stype):
        """ browse service """

        if self._dbus_iface is None:
            raise LegrandError('You need to connect before getting interface name')
        try:
            with self._dbus_service_browser_lock:
                self.pauseDBusLoop()    # We must pause the D-Bus background thread or we may miss the first results from the ServiceBrowser created below (because callbacks for signals are not yet in place)
                print('Generating a new service browser on ' + self._domain + ', service type ' + str(stype))
                browser_path = self._dbus_iface.ServiceBrowserNew(avahi.IF_UNSPEC, avahi.PROTO_UNSPEC, stype, self._domain, dbus.UInt32(0))
                browser_proxy = self._bus.get_object(avahi.DBUS_NAME, browser_path)
                #Got a browser proxy
                print('Using ' + avahi.DBUS_INTERFACE_SERVICE_BROWSER)
                browser_interface = dbus.Interface(browser_proxy, avahi.DBUS_INTERFACE_SERVICE_BROWSER)
                browser_interface.connect_to_signal('AllForNow', self._serviceBrowserDone)
                browser_interface.connect_to_signal('CacheExhausted', self._serviceBrowserCache)
                browser_interface.connect_to_signal('Failure', self._serviceBrowserFailure)
                browser_interface.connect_to_signal('Free', self._serviceBrowserFree)
                browser_interface.connect_to_signal('ItemNew', self._serviceBrowserItemAdded)
                browser_interface.connect_to_signal('ItemRemove', self._serviceBrowserItemRemoved)
                self._dbus_service_browser_finished.clear()
                self.resumeDBusLoop()   # Now we are ready to process signals, resume the D-Bus background thread
                self._dbus_service_browser_finished.wait(30)    # Give at most 30s to get all Bonjour devices 
                
        except:
            raise Exception("DBus exception occurs in browse_service_type with type '%s' and value '%s'" % sys.exc_info()[:2])

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
        temp = self._dbus_iface.ResolveService(
            interface,
            protocol,
            name,
            stype,
            domain,
            avahi.PROTO_UNSPEC,
            dbus.UInt32(0),
            )
        print('Got new service ' + str(temp))
        self.service_database.add(temp)

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
        key = (interface, protocol, name, stype, domain)
        self.service_database.remove(key)

    def _serviceBrowserDone(self):
        """ no more Bonjour service """

        logger.debug('Avahi:AllForNow')
        self._dbus_service_browser_finished.set()

    def _serviceBrowserFailure(self, error):
        """ avahi failure """

        logger.debug('Avahi:Failure')
        logger.warn('Error %s' % error)
        self._dbus_service_browser_finished.set()

    @staticmethod
    def _serviceBrowserFree():
        """ free """

        logger.debug('Avahi:Free')

    @staticmethod
    def _serviceBrowserCache():
        """ cache """

        logger.debug('Avahi:CacheExhausted')


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

    def _reconnect(self):
        """ reconnect can connect if debug was stop or restarted and flush ingoing message """

        self._browser.unconnect()
        self._browser.connect()

    def _browse_generic(self, stype):
        """ connect to DBus, reset database and browse service """
 
        print('Entering _browse_generic()')
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

