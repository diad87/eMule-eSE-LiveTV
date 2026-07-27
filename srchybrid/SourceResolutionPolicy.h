#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace SourceResolutionPolicy
{
	struct Endpoint
	{
		std::uint8_t family;
		std::vector<std::uint8_t> address;
		std::uint16_t port;
	};

	inline std::string CanonicalizeHostname(std::string hostname)
	{
		if (hostname.size() >= 2 && hostname.front() == '[' && hostname.back() == ']')
			hostname = hostname.substr(1, hostname.size() - 2);
		while (!hostname.empty() && hostname.back() == '.')
			hostname.pop_back();
		for (std::string::iterator it = hostname.begin(); it != hostname.end(); ++it) {
			if (*it >= 'A' && *it <= 'Z')
				*it = static_cast<char>(*it - 'A' + 'a');
		}
		return hostname;
	}

	inline std::vector<std::uint8_t> EncodeEndpoint(const Endpoint& endpoint)
	{
		const std::size_t expectedLength =
			endpoint.family == 4 ? 4u : endpoint.family == 6 ? 16u : 0u;
		if (expectedLength == 0 || endpoint.address.size() != expectedLength)
			return std::vector<std::uint8_t>();

		std::vector<std::uint8_t> encoded;
		encoded.reserve(1 + expectedLength + 2);
		encoded.push_back(endpoint.family);
		encoded.insert(encoded.end(), endpoint.address.begin(), endpoint.address.end());
		encoded.push_back(static_cast<std::uint8_t>((endpoint.port >> 8) & 0xff));
		encoded.push_back(static_cast<std::uint8_t>(endpoint.port & 0xff));
		return encoded;
	}

	inline std::vector<std::uint8_t> EncodeEndpointSet(
		const std::vector<Endpoint>& endpoints)
	{
		std::vector<std::vector<std::uint8_t> > encodedEndpoints;
		for (std::vector<Endpoint>::const_iterator it = endpoints.begin();
			it != endpoints.end(); ++it)
		{
			const std::vector<std::uint8_t> encoded = EncodeEndpoint(*it);
			if (!encoded.empty())
				encodedEndpoints.push_back(encoded);
		}
		std::sort(encodedEndpoints.begin(), encodedEndpoints.end());
		encodedEndpoints.erase(
			std::unique(encodedEndpoints.begin(), encodedEndpoints.end()),
			encodedEndpoints.end());

		std::vector<std::uint8_t> canonical;
		for (std::vector<std::vector<std::uint8_t> >::const_iterator it =
			encodedEndpoints.begin(); it != encodedEndpoints.end(); ++it)
		{
			canonical.insert(canonical.end(), it->begin(), it->end());
		}
		return canonical;
	}
}
