# openvpn-snmp
SNMP AgentX for OpenVPN Servers

This tool allows you to track your openvpn servers from snmp. You will get the traffic and connected users of very server, you will also get the traffic per user.

## Install
Copy openvpn.mib to you systems mib directory (usually /usr/share/snmp/mibs)
Create a json configuration file with every server you want to track
openvpn-snmp.json:
```
{
	"servers": 
	[
		{
			"name": "Server 1",
			"pidfile": "/var/run/openvpn.pid",
			"logFile": "/path/to/openvpn-status.log"
		},
		{
			"name": "Server 2",
			"pidfile": "/var/run/openvpn-2.pid",
			"logFile": "/path/to/openvpn-status-2.log"
		}
	]
}
```
These log files need to readable by the python agent.

Enable Agentx-Master on you snmpd.conf
```
master agentx
agentXSocket /var/run/agentx/master
```
Restart snmpd and start the python agent
```bash
sudo python2 openvpn-agent.py -c /path/to/openvpn-snmp.json
```

## Install as service at boot
Copy openvpn-snmp.service into /usr/lib/systemd/system

Copy openvpn-snmp.json into /etc

Enable and start service:
```bash
sudo systemctl --system daemon-reload
sudo systemctl enable openvpn-snmp.service
sudo systemctl start openvpn-snmp.service
```

## How to query?
snmpwalk -v2c -c private localhost .1.3.6.1.3.1991

SNMPv2-SMI::experimental.1991.1.2.1 is a table with every server name, number of connected users and traffic

SNMPv2-SMI::experimental.1991.1.4.1 is a table with every user, its server and traffic