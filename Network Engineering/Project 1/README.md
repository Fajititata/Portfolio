## Network topology
(https://github.com/Fajititata/portfolio/edit/main/Network%20Engineering/Project%201/topology.jpg)

## In this project we'll be configuring a secured network infrastructure such that:
* HQ and their branch offices each have an administrator and accounts created locally on their respective routers.
* All routers to only accept one virtual line through SSH and authenticated (AAA) through Radius server located at INTRANET_SERVER_FARM
* Connections via Telnet, Console and Auxiliary are disallowed
* All passwords are encrypted
* All routers are time synchronized with the NTP server
* OSPF routing is configured on all routers
* VPN is configured between the Tokyo and Jakarta offices
