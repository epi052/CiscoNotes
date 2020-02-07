# CiscoNotes
Notes for Latest Cisco vulns 

### Summary 
[Armis.com](https://www.armis.com/cdpwn/) listed five new zero-day vulnerabilities in the Cisco Discovery Protocol (CDP).  The Armis [white paper](https://go.armis.com/hubfs/White-papers/Armis-CDPwn-WP.pdf) goes into more technical details and also provided the bulk of the information below .  This test will seek to find if vulnerable devices can be identified within the network.

### Vulnerability Background
CDP is a Cisco proprietary Layer 2 (Data Link Layer) network protocol that is used to discover information about locally attached Cisco equipment. CDP is implemented in virtually all Cisco products including switches, routers, IP phones and cameras. Cisco devices ship from the factory with CDP enabled and some of them like VOIP phones rely on the protocol to function properly.

In the examples by Armis they state that an attacker would first need to compromise a device (such as a low security IOT device) within the network to get an initial vlan foothold to possibly take over another networking device.  Their example underlines the fact that this is not an attack that can be simply done over the Internet due to the nature of CDP being a layer 2 protocol. 

In a CDP-capable network, an attacker can only send CDP packets when it is directly connected to a target device.  CDP packets should be terminated by each switch in a normal network. CDP packets have a designated multicast address to which they are sent (01:00:0C:CC:CC:CC), and each CDP-capable switch captures packets sent to this MAC address, and does not forward them throughout the network. 

In the case of VOIP an additional flaw was discovered in the parsing mechanism of CDP packets, enhancing the impact an attacker can achieve using the vulnerability. The VOIP systems referenced in the whitepaper were Cisco-88xx and 78xx. The CDP implementation in the VoIP phones doesn’t validate the destination MAC address of incoming CDP packets, and accepts CDP packets containing unicast/broadcast destination address as well. Any CDP packet that is sent to a switch that is destined to the designated CDP multicast MAC address, will be forwarded by the switch, and not terminated by it. Due to this discrepancy, an attacker can trigger the vulnerability described above by a unicast packet sent directly to target device, or by a broadcast packet sent to all devices in the LAN -- without needing to send the packet directly from the switch to which an VoIP phones is connected to.  

### Synopsis on vulnerable devices 
Switches
NX-OS Stack Overflow in the Power Request TLV (CVE-2020-3119) <- Exploitable (32 bit) with ASLR 

Routers
IOS XR Format String vulnerability in multiple TLVs (CVE-2020-3118)  --- Old IOS XRs are QNX without ASLR and are vulnerable.   Latest version is based on Windriver Linux, the CDP process is 64-bit and ASLR is enabled, so not “trivially” exploitable if at all.

IP Phones Stack Overflow in PortID TLV (CVE-2020-3111) - Cisco-88xx and 78xx VoIP Phones run Linux and the cdp daemon is executed with root privileges.  The only validation of the ethernet header fields is of the source MAC address, which is validated to be any address that isn’t the address of the device itself.  That’s why unicast or broadcast packets work. 

Cisco IP Cameras, as CDP packets are terminated by each switch. In such a network, an attacker can thus only trigger the vulnerability by sending CDP packets when it is directly connected to a target IP camera, which would mean running his attack from the camera’s access switch. In a network that isn’t comprised of Cisco switches, CDP packets may not be terminated at each switch, and an attacker may send the multicast CDP packet to any IP camera in the LAN.

### Testing 
In the environment if the tester is not located on a local network or plugged directly into a network device exploitability would be impossible in all systems but the VOIP phones.  For Layer 3 testing Cisco devices can be scanned for using known management ports and SNMP scans.      

### Analysis
An organization could find vulnerable devices through accessing their purchase records/licenses from Cisco.  Even if the tester was to find external vulnerable assets there may others that they cannot access.  Attackers with inside access to the systems may be at the actual level to perform exploitation.  



### DCNM CISCO VULNS NOTES

### SUMMARY 
According to [Threatpost](https://threatpost.com/cisco-dcnm-flaw-exploit/151949/) proof-of-concept exploit code has been published for critical flaws impacting the Cisco Data Center Network Manager (DCNM) tool for managing network platforms and switches.  CVE-2019-15975, CVE-2019-15976, CVE-2019-15977 impact DCNM, a platform for managing Cisco data centers that run Cisco’s NX-OS — the network operating system used by Cisco’s Nexus-series Ethernet switches and MDS-series Fibre Channel storage area network switches.

Cisco has released an [update and advisory]( https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200102-dcnm-auth-bypass) for the DCNM vulnerabilities.  

The exploits for the vulnerabilities are available [here ](https://srcincite.io/blog/2020/01/14/busting-ciscos-beans-hardcoding-your-way-to-hell.html)

### DCNM artifacts: 
Tested exploitable systems by researcher 
Cisco DCNM 11.2.1 Installer for Windows (64-bit), Cisco DCNM 11.2.1 ISO Virtual Appliance for VMWare, KVM and Bare-metal servers

Application server Cisco DCNM is using is Wildfly (known previously as Jboss)
Virtual Appliance has a serverinfo web applicatio at https://IPaddress/serverinfo/   default creds for this application are admin/nbv_12345
Windows DCNM exploit uri from exploitdb is https://SITE_IP/j_spring_security_check   # https://www.exploit-db.com/exploits/48019
Recommended ports for [DCNM behind a firewall](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/sw/11_0_1/installation/san/b_dcnm_installation_guide_for_san_11_0_1/running_dcnm_behind_firewall.html)
