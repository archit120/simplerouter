/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

using namespace std;

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  // std::cerr << getRoutingTable() << std::endl;

// TODO

  const ethernet_hdr* header = reinterpret_cast<const ethernet_hdr*>(packet.data());

  if(ethertype(packet.data()) != 0x0806 && ethertype(packet.data()) != 0x0800) {
    std::cerr << "Received packet, but type is unknwon, ignoring." << std::endl;
    return;
  }

  if(memcmp(header->ether_dhost, iface->addr.data(), ETHER_ADDR_LEN) && !isBroadcastMAC(header->ether_dhost)) {
    std::cerr << "Received packet, but incorrect MAC, ignoring." << std::endl;
    return;
  }

// Handle ARP Packets first
  print_hdrs(packet);
  if(ethertype(packet.data()) == ethertype_arp) {
    const arp_hdr* arpHeader = reinterpret_cast<const arp_hdr*>(header+1);
    // is it an ARP reply?
    if(ntohs(arpHeader->arp_op) == arp_op_reply) {
      cerr << "Got ARP reply from " << ipToString(arpHeader->arp_sip) << "\n";
      
      auto requests = m_arp.insertArpEntry(createMACBuffer(arpHeader->arp_sha), arpHeader->arp_sip);
      if(requests == nullptr)
        return;
      for(auto packet : requests->packets) {
        // Rehandle all queued up packets
        handlePacket(packet.packet, packet.iface);
      }
      // possible race but unfixable
      m_arp.removeRequest(requests);
    } else {
      // is ARP request for us?
      cerr << "Got ARP request for " << ipToString(arpHeader->arp_tip) << "\n";

      if(arpHeader->arp_tip != iface->ip) {
        cerr << "Ignoring received request because it not for us\n";
        return;
      }

      // Request for us so we have to reply.
      Buffer responsePacket = createARPPacket(false, iface->addr.data(), iface->ip, arpHeader->arp_sha, arpHeader->arp_sip);
      sendPacket(responsePacket, inIface);    
    }
  } else {
    const ip_hdr* ipHeader = reinterpret_cast<const ip_hdr*>(header+1);
    uint16_t ipcksum = ~cksum(ipHeader, ntohs(ipHeader->ip_len));
    if(ipcksum || ntohs(ipHeader->ip_len) < 20) {
      cerr << "Invalid IP Packet. Ignoring\n" ;
      return;
    }
    cerr << "Got an IP Packet for ";
    if(ipHeader->ip_dst != iface->ip) {
      cerr << "someone else. Checking first for different interface on this router\n";
      auto routedInterface = findIfaceByIp(ipHeader->ip_dst);
      Buffer routedPacket = packet;
      ethernet_hdr* routedEthernetHeader = reinterpret_cast<ethernet_hdr*>(routedPacket.data());
      ip_hdr* routedIpHeader = reinterpret_cast<ip_hdr*>(routedEthernetHeader+1);
      if(routedInterface != nullptr) {
        cerr << "IP packet destined for different interface on same device\n";
        // memcpy(routedEthernetHeader->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
        memcpy(routedEthernetHeader->ether_dhost, routedInterface->addr.data(), ETHER_ADDR_LEN);
        routedIpHeader->ip_ttl--;
        routedIpHeader->ip_sum = 0;
        routedIpHeader->ip_sum = cksum(routedIpHeader, ntohs(routedIpHeader->ip_len));
        handlePacket(routedPacket, routedInterface->name);
      } else {
        cerr << "IP packet destined for different interface on different device\n";
        RoutingTableEntry routing = m_routingTable.lookup(ipHeader->ip_dst);
        cerr << "First checking if ARP cache knows where this goes\n"; 
        auto lookup = m_arp.lookup(routedIpHeader->ip_dst);
        if(lookup!=nullptr) {
          cerr << "ARP entry found. Use it\n";
          memcpy(routedEthernetHeader->ether_shost, findIfaceByName(routing.ifName)->addr.data(), ETHER_ADDR_LEN);
          memcpy(routedEthernetHeader->ether_dhost, lookup->mac.data(), ETHER_ADDR_LEN);
          routedIpHeader->ip_ttl--;
          routedIpHeader->ip_sum = 0;
          routedIpHeader->ip_sum = cksum(routedIpHeader, ntohs(routedIpHeader->ip_len));
          sendPacket(routedPacket, routing.ifName);
        } else {
          cerr << "No ARP entry. Queue this packet\n";
          m_arp.queueRequest(routedIpHeader->ip_dst, routedPacket, routing.ifName);
        }
      }
    } else {
      if(ipHeader->ip_p != 1) {
        cerr << "Unknown protocol. Ignoring\n";
        return;
      } 
      cerr << "us with ICMP data. Create Response\n";

      const icmp_hdr* icmpHeader = reinterpret_cast<const icmp_hdr*>(ipHeader + 1);
      uint16_t ipDataLen = ntohs(ipHeader->ip_len) - sizeof(ip_hdr);
      uint16_t icmpcksum = ~cksum(icmpHeader, ipDataLen);
      // cerr << icmpcksum << " " << ipHeader->ip_len << " " <<  sizeof(ip_hdr) << "\n";
      if(icmpcksum != 0) {
        cerr << "ICMP packet invalid cheksum. Ignoring\n";
        return;
      }
        Buffer icmpDataBuffer;

      if(icmpHeader->icmp_type == 8) {
          icmp_hdr responseIcmpHeader;
          responseIcmpHeader.icmp_code = 0;
          responseIcmpHeader.icmp_type = 0;
          responseIcmpHeader.identifier = icmpHeader->identifier;
          responseIcmpHeader.seqno = icmpHeader->seqno;
          icmpDataBuffer.resize(ipDataLen);
          memcpy(icmpDataBuffer.data()+sizeof(icmp_hdr), icmpHeader+1, ipDataLen-sizeof(icmp_hdr));
          memcpy(icmpDataBuffer.data(), &responseIcmpHeader, sizeof(icmp_hdr));
          responseIcmpHeader.icmp_sum = cksum(icmpDataBuffer.data(), icmpDataBuffer.size());
          memcpy(icmpDataBuffer.data(), &responseIcmpHeader, sizeof(icmp_hdr));
      } else {
        cerr << "Unkown ICMP type\n";
        return;
      }
      auto responsePacket = createIPPacket(iface->addr.data(), iface->ip, header->ether_shost, ipHeader->ip_src, 
        icmpDataBuffer.data(), icmpDataBuffer.size(),64, 1);
      sendPacket(responsePacket, m_routingTable.lookup(ipHeader->ip_src).ifName);
      // icmpHeader
    }

  }
  
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
