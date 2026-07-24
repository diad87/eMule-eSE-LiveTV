#pragma once

#include <ctime>

namespace KadPublishPolicy
{
	inline bool IsFastRefresh(std::time_t now, std::time_t lastPublish,
		std::time_t republishInterval, std::time_t tolerance)
	{
		if (republishInterval <= tolerance)
			return false;
		if (now < lastPublish)
			return true;
		return now - lastPublish < republishInterval - tolerance;
	}
}
