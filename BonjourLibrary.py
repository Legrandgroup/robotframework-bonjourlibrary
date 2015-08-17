#!/usr/bin/python
# -*- coding: utf-8 -*-

""" Legrand MP5B """

from __future__ import division

import re
import sys
import time

from dbus.mainloop.glib import DBusGMainLoop
import avahi
import avahi.ServiceTypeDatabase
import dbus
import gobject

from common import LegrandError, StoppingError
from ToolLibrary import ToolLibrary

DBusGMainLoop(set_as_default=True)


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

        mac = ToolLibrary.mac_string(mac)
        mac_manufacturer = ToolLibrary.mac_manufacturer(mac)
        for key in self._database.keys():
            temp = self.get_info_from_key(key)
            if temp is not None:
                mac_product = temp[1]
                bonjour_mac = ToolLibrary.mac_string(mac_manufacturer + mac_product)
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

    def __init__(self, domain, loop):
        """ DBus connection """

        self._domain = domain
        self._loop = loop
        self._bus = None
        self._avahi_proxy = None
        self._server = None
        self.service_database = ServiceDatabase()

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

    def connect(self):
        """ DBus connection """

        if not self._bus:
            try:
                self._bus = dbus.SystemBus(private=True)
                self._avahi_proxy = self._bus.get_object(avahi.DBUS_NAME, avahi.DBUS_PATH_SERVER)
                self._server = dbus.Interface(self._avahi_proxy, avahi.DBUS_INTERFACE_SERVER)
            except:
                raise LegrandError("DBus exception occurs with type '%s' and value '%s'" % sys.exc_info()[:2])
            logger.debug("DBus connected passed on '%s'" % self._bus)
            self._wait_daemon()
        else:
            logger.debug('DBus connect failed on existing instance')

    def unconnect(self):
        """ DBus unconnect """

        if self._bus:
            try:
                self._bus.close()
            except:
                raise LegrandError("DBus exception occurs with type '%s' and value '%s'" % sys.exc_info()[:2])
            logger.debug("DBus close passed on '%s'" % self._bus)
            self._bus = None
            self._avahi_proxy = None
            self._server = None
        else:
            logger.debug('DBus close failed on null instance')

    def get_version(self):
        """ get version """

        if self._server is None:
            raise LegrandError('You need to connect before getting version')
        else:
            version = self._server.GetVersionString()
            return version

    def get_interface_name(self, interface_index):
        """ get interface name from index """

        if self._server is None:
            raise LegrandError('You need to connect before getting interface name')
        else:
            interface_name = self._server.GetNetworkInterfaceNameByIndex(interface_index)
            return interface_name

    def get_state(self):
        """ get state """

        if self._server is None:
            raise LegrandError('You need to connect before getting interface name')
        else:
            state = self._server.GetState()
            return state

    def browse_service_type(self, stype):
        """ browse service """

        if self._server is None:
            raise LegrandError('You need to connect before getting interface name')
        try:
            browser_path = self._server.ServiceBrowserNew(avahi.IF_UNSPEC, avahi.PROTO_UNSPEC, stype, self._domain, dbus.UInt32(0))
            browser_proxy = self._bus.get_object(avahi.DBUS_NAME, browser_path)
            browser_interface = dbus.Interface(browser_proxy, avahi.DBUS_INTERFACE_SERVICE_BROWSER)
            browser_interface.connect_to_signal('AllForNow', self._service_finish)
            browser_interface.connect_to_signal('CacheExhausted', self._service_cache)
            browser_interface.connect_to_signal('Failure', self._service_failure)
            browser_interface.connect_to_signal('Free', self._service_free)
            browser_interface.connect_to_signal('ItemNew', self._service_new)
            browser_interface.connect_to_signal('ItemRemove', self._service_remove)
        except:
            raise LegrandError("DBus exception occurs in browse_service_type with type '%s' and value '%s'" % sys.exc_info()[:2])

    def _service_new(
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
        temp = self._server.ResolveService(
            interface,
            protocol,
            name,
            stype,
            domain,
            avahi.PROTO_UNSPEC,
            dbus.UInt32(0),
            )
        self.service_database.add(temp)

    def _service_remove(
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

    def _service_finish(self):
        """ no more Bonjour service """

        logger.debug('Avahi:AllForNow')
        self._loop.quit()

    def _service_failure(self, error):
        """ avahi failure """

        logger.debug('Avahi:Failure')
        logger.warn('Error %s' % error)
        self._loop.quit()

    @staticmethod
    def _service_free():
        """ free """

        logger.debug('Avahi:Free')

    @staticmethod
    def _service_cache():
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

    DAEMON = '/etc/init.d/avahi-daemon'

    def __init__(self, domain='local'):
        self._domain = domain
        self._loop = gobject.MainLoop()
        self._browser = BonjourWrapper(self._domain, self._loop)

    def _reconnect(self):
        """ reconnect can connect if debug was stop or restarted and flush ingoing message """

        self._browser.unconnect()
        self._browser.connect()

    def _browse_generic(self, stype):
        """ connect to DBus, reset database and browse service """

        self._reconnect()
        self._browser.service_database.reset()
        self._browser.browse_service_type(stype)
        try:
            logger.debug('DBus loop running')
            self._loop.run()
        except (KeyboardInterrupt, SystemExit):
            self._loop.quit()
            raise StoppingError("Exit from glib loop with type '%s' and value '%s'" % sys.exc_info()[:2])
        except:
            self._loop.quit()
            raise LegrandError("DBus exception occurs in browse_generic with type '%s' and value '%s'" % sys.exc_info()[:2])
        else:
            logger.debug('DBus loop ending with database:%s' % self._browser.service_database)

    def restart(self):
        """ Restart Avahi service.

        Example:
        | Restart |
        """

        ToolLibrary.run(BonjourLibrary.DAEMON, 'restart')
        self._browser.connect()

    def stop(self):
        """ Stopping Avahi service.

        Example:
        | Stop |
        """

        self._browser.unconnect()
        ToolLibrary.run(BonjourLibrary.DAEMON, 'stop')

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
            raise LegrandError("Service '%s' expected on '%s'" % (stype, mac))
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


if __name__ == '__main__':
    from console_logger import LOGGER as logger

    try:
        input = raw_input
    except NameError:
        pass

    MAC = '00:04:74:05:00:f0'
    IP = '10.10.8.39'
    BL = BonjourLibrary('local')
    BL.restart()
    BL.stop()
    BL.restart()
    input('Press enter & "Enable UPnP/Bonjour" on web interface')
    assert IP == BL.get_ip(MAC, '_http._tcp')
    DATA = BL.check_run(IP, '_http._tcp')
    BL.get_apname(DATA)
    input('Press enter & "Disable UPnP/Bonjour" on web interface')
    BL.check_stop(IP, '_http._tcp')
else:
    from robot.api import logger

