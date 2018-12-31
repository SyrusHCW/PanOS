{% for item in palo_node0_config %}
#Test VPN Config and build
#!/usr/bin/python3

import datetime
import random
import sys
import time


from pandevice import device
from pandevice import firewall
from pandevice import network


HOSTNAME = '192.168.1.253'
USERNAME = 'admin'
PASSWORD = 'admin'

vlans =[]
zones_names =[]
routing_instance = []
addresses =[]

trust_access = 'absent'
trust_voice = 'absent'
trust_secure = 'absent'
trust_guestwlan = 'absent'
trust_printer = 'absent'
trust_management = 'present'
trust_airtame = 'absent'

zones = [["trust_access", 50, "vr_master"], \
        ["trust_voice", 51, "vr_master"], \
        ["trust_secure", 52, "vr_master"], \
        ["trust_guestwlan", 53,"vr_trust_guestwlan"], \
        ["trust_printer", 54, "vr_master"], \
        ["trust_management", 55, "vr_master"], \
        ["trust_airtame", 56, "vr_airtame"]]

trust_guestwlan_ip_cidr = '172.16.3.1/24'
trust_management_ip_cidr = '172.16.2.1/24'
trust_airtame_ip_cidr = '172.16.1.1/24'


remote_vpn_ip = '{{ item.remote_vpn_ip }}'
local_vpn_ip = '{{ item.local_vpn_ip }}'
cidr = '{{ item.vpn_cidr }}'

untrust_cidr = '{0}{1}'.format(local_vpn_ip, cidr)

    #This will append present or absent to list if a vlans

zones[0].append(trust_access)
zones[1].append(trust_voice)
zones[2].append(trust_secure)
zones[3].append(trust_guestwlan)
zones[4].append(trust_printer)
zones[5].append(trust_management)
zones[6].append(trust_airtame)

    
zones[3].append(trust_guestwlan_ip_cidr)
zones[5].append(trust_management_ip_cidr)
zones[6].append(trust_airtame_ip_cidr)
    

    #This will append a list of present vlans to the list variable 'vlan'
for state in range(0,7):
        if (zones[state][3]) == "present":
            vlans.append(zones[state][1])
            zones_names.append(zones[state][0])
            routing_instance.append(zones[state][2])
            addresses.append(zones[state][4])

    # Before we begin, you'll need to use the pandevice documentation both
    # for this example and for any scripts you may write for yourself.  The
    # docs can be found here:
    #
    # http://pandevice.readthedocs.io/en/latest/reference.html
    #
    # First, let's create the firewall object that we want to modify.

fw = firewall.Firewall(HOSTNAME, USERNAME, PASSWORD)

print('Firewall system info: {0}'.format(fw.refresh_system_info()))

    # Sanity Check #1: the intent here is that the interface we
    # specified above should not already be in use.  If the interface is
    # already in use, then just quit out.


#Creates Untrust Interface


untrust_int = network.EthernetInterface("ethernet1/1", \
        mode = "layer3", \
        ip = untrust_cidr)


fw.add(untrust_int)
untrust_int.create()
print(untrust_int)

#Creates Management Untagged Gateway Interface


mgmt_int = network.EthernetInterface("ethernet1/2", \
        mode = "layer3", \
        ip = '{{ item.mgmt_gw }}')


fw.add(mgmt_int)
mgmt_int.create()
print(mgmt_int)


# creates tunnel interface for VPN to Knowhere


tunnel_int = network.TunnelInterface("tunnel.100", \
        ip = '{{ item.remote_p2p_ip }}', \
        ipv6_enabled = False)


fw.add(tunnel_int)
tunnel_int.create()
print(tunnel_int)


#Creates trust_fwh_vpn secuirty zone


vpn_zone = network.Zone("trust_fwh_vpn", \
        mode = "layer3", \
        interface = "tunnel.100")


fw.add(vpn_zone)
vpn_zone.create()
print(vpn_zone)


#Creates trust_management secuirty zone


mgmt_zone = network.Zone("trust_management", \
        mode = "layer3", \
        interface = "ethernet1/2")


fw.add(mgmt_zone)
mgmt_zone.create()
print(mgmt_zone)


#Creates untrust secuirty zone


un_zone = network.Zone("untrust", \
        mode = "layer3", \
        interface = "ethernet1/1")


fw.add(un_zone)
un_zone.create()
print(un_zone)


#creates master vr_master virtual router and assoictes ethernet1/1


vr_master = network.VirtualRouter("vr_master", \
        interface = ["ethernet1/1", "tunnel.100", "ethernet1/2"])


fw.add(vr_master)
vr_master.create()
print(vr_master)


# Creates IKE Crypto Profile


ikecp = network.IkeCryptoProfile("ICP-DH_G5-AUTH_SHA256-EN_AES256", \
        dh_group = "group5", \
        authentication = "sha256", \
        encryption = "aes-256-cbc", \
        lifetime_seconds = "3600")


fw.add(ikecp)
ikecp.create() 
print(ikecp) 
   

# Create IPSec Crypto Profile


ipseccp = network.IpsecCryptoProfile('IPCP-EN-AES256_AU-AES256_DH5', \
        esp_encryption = "aes-256-cbc", \
        esp_authentication = "sha256", \
        dh_group = "group5", \
        lifetime_seconds = "3600")


fw.add(ipseccp)
ipseccp.create()
print(ipseccp)


# Configure IKE Gateway 


ikegw = network.IkeGateway("IKE-GATE-FWH-LAB123", \
        version = "ikev2", \
        peer_ip_type = "ip", \
        peer_ip_value = remote_vpn_ip, \
        interface = "ethernet1/1", \
        local_ip_address = untrust_cidr, \
        auth_type = "pre-shared-key", \
        pre_shared_key = '{{ item.vpn_psk }}', \
        local_id_type = "ipaddr", \
        local_id_value = local_vpn_ip, \
        peer_id_type = "ipaddr", \
        peer_id_value = remote_vpn_ip, \
        ikev2_crypto_profile = "ICP-DH_G5-AUTH_SHA256-EN_AES256")


fw.add(ikegw)
ikegw.create()
print(ikegw)


# Create IPSec tunnel


ipsec_tun = network.IpsecTunnel("IPSEC-LAB-TUN", \
        tunnel_interface = "tunnel.100", \
        anti_replay = True, \
        type = "auto-key", \
        ak_ike_gateway = "IKE-GATE-FWH-LAB123", \
        ak_ipsec_crypto_profile = 'IPCP-EN-AES256_AU-AES256_DH5')


fw.add(ipsec_tun)
ipsec_tun.create()
print(ipsec_tun)


# Create Static Route for DC


sr = network.StaticRoute("SR-10.0.0.0", \
        destination = "10.0.0.0/8", \
        nexthop_type = "ip-address", \
        nexthop = '{{ item.Knowhere_p2p_ip }}')


fw.add(sr)
sr.create()
print(sr)


fw.commit()
print("committing")


time.sleep(120)
print("committed")

{% endfor %}
