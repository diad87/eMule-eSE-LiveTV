#include "stdafx.h"

#include "LiveRecoveryTransportAdapter.h"

#include "UpDownClient.h"
#include "eMuleAI/Address.h"

ese::live::LiveRecoveryEndpoint LiveRecoveryTransportAdapter::EndpointOf(
	const CUpDownClient* const peer)
{
	if (peer == NULL || peer->GetUserPort() == 0u)
		return ese::live::LiveRecoveryEndpoint();

	CAddress address;
	if (peer->IsIPv6OnlyEndpoint()) {
		address = peer->GetIPv6Address();
	} else {
		const uint32 ip = peer->GetIP();
		if (ip != 0u && ip != INADDR_NONE)
			address = CAddress::FromIPv4NetworkOrder(ip);
		else if (peer->HasIPv6Address())
			address = peer->GetIPv6Address();
		else {
			const uint32 connect_ip = peer->GetConnectIP();
			if (connect_ip != 0u && connect_ip != INADDR_NONE)
				address = CAddress::FromIPv4NetworkOrder(connect_ip);
		}
	}
	if (address.GetType() == CAddress::None)
		return ese::live::LiveRecoveryEndpoint();
	const std::string text = address.ToString();
	return ese::live::LiveRecoveryEndpoint::FromText(
		address.GetType() == CAddress::IPv6 ? 6u : 4u,
		text.c_str(),
		peer->GetUserPort());
}
