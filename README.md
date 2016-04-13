# Port Scanner

This tool can be used to scan arbitrary networks for open ports. The following command line arguments are supported:

|Argument|Description|Example|
|---|---|---|
|`--hosts`|A comma-separated list of IP addresses and/or IP address ranges in the form `a.b.c.d-w.x.y.z`.|`--hosts=192.168.1.1,192.168.10.0-192.168.10.255`|
|`--hosts-file`|The location of a text file containing IP addresses and/or IP address ranges as described above. Multiple lines are supported.|`--hosts-file=myhosts.txt`|
|`--ports`|A comma-separated list of ports and/or port ranges in the form `a-b`.|`--ports=0-1023,3389,8080`|
|`--ports-file`|The location of a text file containing ports and/or port ranges as described above. Multiple lines are supported.|`--ports-file=myports.txt`|
|`--ping`|If this flag is given, hosts will receive an ICMP ping before being scanned. (Only hosts that respond will be scanned.)|`--ping`|
|`--protocols`|A comma-separated list of protocols to use for port scanning. Names are case-insensitive. Currently supported: TCP, UDP\*.|`--protocols=tcp,udp`|
|`--html`|If given, a simple HTML report will be written to this location when the scan is complete.|`--html=myreport.html`|

All command line arguments are optional. If no hosts, ports, or protocols are given, the following defaults are used:

|Argument Type|Default Value|
|---|---|
|Hosts|`127.0.0.1`|
|Ports|`0-1023`|
|Protocols|`tcp`|

\*UDP scanning is very unreliable and produces many false positives.