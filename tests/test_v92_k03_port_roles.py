#!/usr/bin/env python3
"""K03 regression guard for local-versus-advertised port roles."""

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def source(relative_path: str) -> str:
    # Every token checked here is ASCII. Latin-1 gives a lossless one-byte
    # projection even for older eMule sources that are not UTF-8.
    return (ROOT / relative_path).read_bytes().decode("latin-1")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


client_list = source("srchybrid/ClientList.cpp")
require(
    "thePrefs.GetPort() == contact->GetTCPPort()" not in client_list,
    "Kad self-detection must not compare a public contact with the local TCP port",
)
require(
    client_list.count(
        "theApp.GetAdvertisedTcpPort() == contact->GetTCPPort()"
    )
    == 3,
    "all three Kad self-detection paths must use the advertised TCP port",
)

part_file = source("srchybrid/PartFile.cpp")
require(
    "thePrefs.GetPort() == port" not in part_file,
    "source self-detection must not compare a public source with the local TCP port",
)
require(
    part_file.count("theApp.GetAdvertisedTcpPort() == port") == 2,
    "both active IPv4 source self-detection paths must use the advertised TCP port",
)

web_server = source("srchybrid/WebServer.cpp")
require(
    "PORTTESTURL, thePrefs.GetPort(), thePrefs.GetUDPPort()" not in web_server,
    "the web connection-test link must not publish local mapper ports",
)
require(
    "PORTTESTURL, theApp.GetAdvertisedTcpPort()" in web_server
    and "theApp.GetAdvertisedUdpPort(), thePrefs.GetLanguageID()" in web_server,
    "the web connection-test link must publish the confirmed advertised pair",
)

# Representative local-role guards: K03 must not turn bind/firewall/mapper
# inputs into public ports during a future bulk replacement.
require(
    "Create(thePrefs.GetPort(), SOCK_STREAM" in source("srchybrid/ListenSocket.cpp"),
    "TCP listener bind must keep the local preference port",
)
require(
    "CAsyncSocket::Create(thePrefs.GetUDPPort(), SOCK_DGRAM"
    in source("srchybrid/ClientUDPSocket.cpp"),
    "UDP listener bind must keep the local preference port",
)
require(
    "nForceTCPPort ? nForceTCPPort : thePrefs.GetPort()"
    in source("srchybrid/EmuleDlg.cpp"),
    "mapper input must keep the local TCP preference port",
)
require(
    "return thePrefs.GetUDPPort();"
    in source("srchybrid/kademlia/kademlia/Prefs.cpp"),
    "Kad GetInternKadPort must remain explicitly local",
)

project = source("srchybrid/emule.vcxproj")
require(
    "PartFile.utf8.cpp" not in project and "WebServer_original.cpp" not in project,
    "historical source copies must remain excluded from the production build",
)

base_client = source("srchybrid/BaseClient.cpp")
require(
    "? theApp.GetAdvertisedUdpPort() : 0;" in base_client,
    "the public Kad field in CT_EMULE_UDPPORTS must use the advertised UDP port",
)

kad_listener = source("srchybrid/kademlia/net/KademliaUDPListener.cpp")
require(
    "endpoint.udp_port = publicV6KadPort;" in kad_listener
    and "theApp.GetAdvertisedV6UdpPort()" in kad_listener,
    "the public Kad6 IPv6 endpoint must use the advertised IPv6 UDP port",
)
require(
    "const uint16 publicKadPort =" in kad_listener
    and "natmap::PreferredDirectRoute::MappedV4" in kad_listener
    and "? theApp.GetAdvertisedUdpPort()" in kad_listener
    and ": theApp.GetLocalUdpPort();" in kad_listener,
    "the public Kad6 IPv4 endpoint must use the advertised UDP port",
)
require(
    "CKadTagUInt16(TAG_SOURCEUPORT, advertisedKadPort)" in kad_listener
    and "TAG_SOURCEUPORT, CKademlia::GetPrefs()->GetInternKadPort()"
    not in kad_listener,
    "Kad hello serialization must not publish the internal UDP port",
)

search = source("srchybrid/kademlia/kademlia/Search.cpp")
require(
    search.count("TAG_SOURCEUPORT, advertisedKadPort") == 3
    and "TAG_SOURCEUPORT, CKademlia::GetPrefs()->GetInternKadPort()"
    not in search,
    "all classic Kad source tags must publish the common advertised UDP port",
)
require(
    "const uint16 uLiveKadUDP =\n\t\t\t\t\ttheApp.GetAdvertisedUdpPort();"
    in search,
    "Live Kad publication must use the common advertised UDP port",
)

kad6_gateway = source("srchybrid/Kad6GatewaySocket.cpp")

lt4_source_bind_start = kad6_gateway.index("void CKad6OriginSocket::LT4SourceBind(")
lt4_source_bind_end = kad6_gateway.index(
    "\nvoid CKad6OriginSocket::LT4Publish(", lt4_source_bind_start
)
lt4_source_bind = kad6_gateway[lt4_source_bind_start:lt4_source_bind_end]
require(
    "const uint16_t tcpPort = useV6\n"
    "    ? theApp.GetAdvertisedV6TcpPort()\n"
    "    : theApp.GetAdvertisedTcpPort();" in lt4_source_bind,
    "LT4SourceBind must select the advertised TCP authority for its family",
)
require(
    "const uint16_t udpPort = useV6\n"
    "    ? theApp.GetAdvertisedV6UdpPort()\n"
    "    : theApp.GetAdvertisedUdpPort();" in lt4_source_bind,
    "LT4SourceBind must select the advertised UDP authority for its family",
)
require(
    "tcpPort == 0 || udpPort == 0" in lt4_source_bind
    and "tcpPort, udpPort" in lt4_source_bind
    and "bound.virtual_endpoint.tcp_port = tcpPort;" in lt4_source_bind
    and "bound.virtual_endpoint.udp_port = udpPort;" in lt4_source_bind,
    "LT4SourceBind must use its selected advertised pair for availability, logs, and wire endpoint",
)
require(
    "GetInternKadPort" not in lt4_source_bind
    and "GetExternalKadPort" not in lt4_source_bind,
    "LT4SourceBind must not publish Kad internal or external preference ports",
)

linter = subprocess.run(
    [sys.executable, str(ROOT / "tools" / "check_direct_port_usage.py")],
    cwd=ROOT,
    capture_output=True,
    text=True,
)
require(
    linter.returncode == 0,
    "direct-port inventory must remain reviewed and stable: "
    + (linter.stdout + linter.stderr).strip(),
)

print("test_v92_k03_port_roles: 22 checks, 0 failures")
