//This file is part of eMule AI
//Copyright (C)2026 eMule AI
// Integrated into eSE (eMule Streaming Engine)

#include "stdafx.h"
#include "eMuleAI/FastKad.h"
#include "Opcodes.h"

using namespace Kademlia;

namespace Kademlia
{
	CFastKad	fastKad;

	CFastKad::CFastKad()
	{
		AddResponseTime(0, CLOCKS_PER_SEC); // Default to 1 second
	}

	CFastKad::~CFastKad()
	{
		for (std::map<uint32, ResponseTimeEntry*>::const_iterator it = m_mapResponseTimes.begin(); it != m_mapResponseTimes.end(); ++it)
			delete it->second;
	}

	void CFastKad::ShutdownCleanup()
	{
		for (std::map<uint32, ResponseTimeEntry*>::const_iterator it = m_mapResponseTimes.begin(); it != m_mapResponseTimes.end(); ++it)
			delete it->second;
		m_mapResponseTimes.clear();

		// Reset cached statistics after cleanup.
		m_fResponseTimeMean = 0.0;
		m_fResponseTimeVariance = 0.0;
		m_clkEstResponseTime = 0;
	}

	void CFastKad::AddResponseTime(uint32 uIP, clock_t clkResponseTime)
	{
		clock_t const clkNow = clock();
		ResponseTimeEntry* entry;
		std::map<uint32, ResponseTimeEntry*>::const_iterator it = m_mapResponseTimes.find(uIP);
		if (it == m_mapResponseTimes.end())
		{
			if (m_mapResponseTimes.size() >= s_uMaxResponseTimes) // Don't keep more than s_uMaxResponseTimes entries
			{
				// Remove oldest
				clock_t clkOldestAge = 0;
				std::map<uint32, ResponseTimeEntry*>::iterator itOldest = m_mapResponseTimes.end();
				for (std::map<uint32, ResponseTimeEntry*>::iterator it2 = m_mapResponseTimes.begin(); it2 != m_mapResponseTimes.end(); ++it2)
				{
					clock_t clkAge = clkNow - it2->second->m_clkLastReferenced;
					if (clkAge >= clkOldestAge && clkAge > (5 * 60 * CLOCKS_PER_SEC)) // Don't drop entries that are less than 5 minutes old to reduce fluctuations 
					{
						clkOldestAge = clkAge;
						itOldest = it2;
					}
				}
				if (itOldest != m_mapResponseTimes.end())
				{
					delete itOldest->second;
					m_mapResponseTimes.erase(itOldest);
				}
				else
				{
					return; // Not possible to add at this time!
				}
			}
			entry = new ResponseTimeEntry;
			entry->m_clkResponseTime = clkResponseTime;
		}
		else
		{
			entry = it->second;
			entry->m_clkResponseTime = clkResponseTime;
		}
		entry->m_clkLastReferenced = clkNow;
		m_mapResponseTimes[uIP] = entry;

		RecalculateResponseTime();
	}

	void CFastKad::RecalculateResponseTime()
	{
		double fResponseTimeSum = 0.0;
		double fResponseTimeCount = static_cast<double>(m_mapResponseTimes.size());
		double fResponseTimeVarianceSum = 0.0;

		double fResponseTimeCountMissing;
		if (m_mapResponseTimes.size() < s_uMaxResponseTimes)
			fResponseTimeCountMissing = static_cast<double>(s_uMaxResponseTimes) - fResponseTimeCount;
		else
			fResponseTimeCountMissing = 0.0;

		// Calculate mean
		for (std::map<uint32, ResponseTimeEntry*>::const_iterator it = m_mapResponseTimes.begin(); it != m_mapResponseTimes.end(); ++it)
		{
			fResponseTimeSum += static_cast<double>(it->second->m_clkResponseTime);
		}
		fResponseTimeSum += fResponseTimeCountMissing * static_cast<double>(CLOCKS_PER_SEC);
		m_fResponseTimeMean = fResponseTimeSum / static_cast<double>(s_uMaxResponseTimes);

		// Calculate variance
		if (m_mapResponseTimes.size() > 1)
		{
			for (std::map<uint32, ResponseTimeEntry*>::const_iterator it = m_mapResponseTimes.begin(); it != m_mapResponseTimes.end(); ++it)
			{
				fResponseTimeVarianceSum += pow(static_cast<double>(it->second->m_clkResponseTime) - m_fResponseTimeMean, 2.0);
			}
		}
		fResponseTimeVarianceSum += fResponseTimeCountMissing * static_cast<double>(CLOCKS_PER_SEC);
		m_fResponseTimeVariance = fResponseTimeVarianceSum / static_cast<double>(s_uMaxResponseTimes - 1);

		// Estimate max expected response time with ~95% confidence and add 100ms to the result (however never exceed 3 seconds)
		m_clkEstResponseTime = min(3 * CLOCKS_PER_SEC, static_cast<clock_t>(m_fResponseTimeMean + 2 * sqrt(m_fResponseTimeVariance)) + CLOCKS_PER_SEC / 10);
	}
}
