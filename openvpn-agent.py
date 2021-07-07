#!/usr/bin/env python2
#
# openvpn-snmp agentx
# Copyright (c) 2015 Philipp Helo Rehs
#
# Based on python-netsnmpagent simple example agent
# https://github.com/pief/python-netsnmpagent
# Copyright (c) 2013 Pieter Hollants <pieter@hollants.com>
# Licensed under the GNU Public License (GPL) version 3
#

import sys
import os
import signal
import json
import re
import logging
import netsnmpagent
import argparse
try:
    import daemon
except ImportError:  # pragma: no cover
    daemon = False

# Log to file
#logging.basicConfig(level=logging.INFO, filename="test.log")

# Log to stdout or syslog via systemd
logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)


class OpenVpnAgentX(object):

    def __init__(self):
        self._parse_args()
        self.run()

    def _parse_args(self):
        # Process command line arguments
        parser = argparse.ArgumentParser(description='SNMP AgentX for Openvpn')
        parser.add_argument(
            '-m',
            '--mastersocket',
            dest="mastersocket",
            help='Sets the transport specification for the master agent\'s AgentX socket',
            default="/var/run/agentx/master"
        )
        parser.add_argument(
            "-p",
            "--persistencedir",
            dest="persistencedir",
            help="Sets the path to the persistence directory",
            default="/var/lib/net-snmp"
        )
        parser.add_argument(
            "-c",
            "--configfile",
            dest="configfile",
            help="path of the json configuration file",
            default="/etc/openvpn-snmp.json"
        )
        parser.add_argument(
            "-f",
            "--foreground",
            dest="foreground",
            help="run in foreground",
            default=False,
            action='store_true'
        )
        self.options = parser.parse_args()

        if not os.access(self.options.mastersocket, os.R_OK):
            logger.critical("Can't connect to MasterSocket, run as root")
            sys.exit(1)

    def _parse_config(self):
        with open(self.options.configfile) as data_file:
            self.serverList = json.load(data_file)

    def _create_snmp_objects(self):
        try:
            self.agent = netsnmpagent.netsnmpAgent(
                AgentName="OpenVpnAgent",
                MasterSocket=self.options.mastersocket,
                PersistenceDir=self.options.persistencedir,
                MIBFiles=["/usr/share/snmp/mibs/openvpn.mib"]
            )
        except netsnmpagent.netsnmpAgentException as e:
            logger.critical(e)
            sys.exit(1)

        self.snmp = dict()
        self.snmp['serverTable'] = self.agent.Table(
            oidstr="OPENVPN-MIB::openvpnServerTable",
            indexes=[
                self.agent.Unsigned32()
            ],
            columns=[
                (1, self.agent.Integer32(0)),
                (2, self.agent.DisplayString()),
                (3, self.agent.Unsigned32(0)),
                (4, self.agent.Counter32(0)),
                (5, self.agent.Counter32(0))
            ],
            counterobj=self.agent.Unsigned32(
                oidstr="OPENVPN-MIB::openvpnServerTableLength"
            )
        )

        self.snmp['userTable'] = self.agent.Table(
            oidstr="OPENVPN-MIB::openvpnUserTable",
            indexes=[
                self.agent.Unsigned32()
            ],
            columns=[
                (1, self.agent.Integer32(0)),
                (2, self.agent.DisplayString()),
                (3, self.agent.DisplayString()),
                (4, self.agent.Counter32(0)),
                (5, self.agent.Counter32(0)),
                (6, self.agent.DisplayString())
            ],
            counterobj=self.agent.Unsigned32(
                oidstr="OPENVPN-MIB::openvpnUserTableLength"
            )
        )
        try:
            self.agent.start()
        except netsnmpagent.netsnmpAgentException as e:
            logger.critical(e)
            sys.exit(1)

        logger.info("AgentX connection to snmpd established.")

    def _signalHandler(signum, frame):
        self._loop = False

    def run(self):
        self._loop = True
        self._parse_config()
        if daemon and not self.options.foreground:
            context = daemon.DaemonContext()
            context.signal_map = {
                signal.SIGTERM: self._signalHandler,
                # signal.SIGHUP: 'terminate',
                signal.SIGUSR1: self._parse_config,
            }
            with context:
                self._create_snmp_objects()
                self._runLoop()
        else:
            self._create_snmp_objects()
            logging.info("Running in foreground")
            self._runLoop()

    def _runLoop(self):
        while (self._loop):
            # Block and process SNMP requests, if available
            self.agent.check_and_process()

            self.snmp['serverTable'].clear()
            self.snmp['userTable'].clear()
            user_index = 0
            for i in range(0, len(self.serverList['servers'])):
                s = self.serverList['servers'][i]
                if os.path.exists(s['pidfile']):
                    if os.access(s['logFile'], os.R_OK):
                        fh = open(s['logFile'], "r")
                        fileContent = fh.readlines()
                        serverData = self.parse_openvpn_status_file(fileContent)
                        tmpRow = self.snmp['serverTable'].addRow(
                            [self.agent.Unsigned32(i)]
                        )
                        tmpRow.setRowCell(
                            1,
                            self.agent.Integer32(i+1)
                        )
                        tmpRow.setRowCell(
                            2,
                            self.agent.DisplayString(s['name'])
                        )
                        tmpRow.setRowCell(
                            3,
                            self.agent.Unsigned32(len(serverData['users']))
                        )
                        tmpRow.setRowCell(
                            4,
                            self.agent.Counter32(serverData['send'])
                        )
                        tmpRow.setRowCell(
                            5,
                            self.agent.Counter32(serverData['recv'])
                        )
                        for u in serverData['users']:
                            user_index = user_index+1
                            tmpUser = self.snmp['userTable'].addRow(
                                [self.agent.Unsigned32(user_index)]
                            )
                            tmpUser.setRowCell(
                                1,
                                self.agent.Integer32(user_index)
                            )
                            tmpUser.setRowCell(
                                2,
                                self.agent.DisplayString(u['name'])
                            )
                            tmpUser.setRowCell(
                                3,
                                self.agent.DisplayString(s['name'])
                            )
                            tmpUser.setRowCell(
                                4,
                                self.agent.Counter32(u['send'])
                            )
                            tmpUser.setRowCell(
                                5,
                                self.agent.Counter32(u['recv'])
                            )
                            tmpUser.setRowCell(
                                6,
                                self.agent.DisplayString(u['date'])
                            )
                    else:
                        logger.warning("{0} is not readable".format(s['logFile']))

        logger.info("Terminating.")
        self.agent.shutdown()

    def parse_openvpn_status_file(self, lines):
        regex = r'^([\w[\w.-]+),([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+),([0-9]+),([0-9]+),(.*)'
        userlist = []
        server = {'send': 0, 'recv': 0}
        for line in lines:
            m = re.match(regex, line)
            if m is not None:
                t_send = int(m.group(4))
                t_recv = int(m.group(3))
                user = {
                    'name': m.group(1),
                    'ip': m.group(2),
                    'recv': t_recv,
                    'send': t_send,
                    'date': m.group(5)
                }
                userlist.append(user)
                server['send'] = server['send'] + t_send
                server['recv'] = server['recv'] + t_recv

        server['users'] = userlist
        return server


app = OpenVpnAgentX()
app.run()
