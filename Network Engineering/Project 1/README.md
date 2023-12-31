## Network topology
![topology](https://github.com/Fajititata/portfolio/assets/88973742/d4dd13ba-a71b-4cc8-8e97-27dda47e39ba)

## In this project we'll be configuring a secured network infrastructure such that:
* HQ and their branch offices each have an administrator and accounts created locally on their respective routers.
* All routers to only accept one virtual line through SSH and authenticated (AAA) through Radius server located at INTRANET_SERVER_FARM
* Connections via Telnet, Console and Auxiliary are disallowed
* All passwords are encrypted
* All routers are time synchronized with the NTP server
* OSPF routing is configured on all routers
* VPN is configured between the Tokyo and Jakarta offices
