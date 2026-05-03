//This file is part of eMule AI
//Copyright (C)2026 eMule AI
// Integrated into eSE (eMule Streaming Engine)

#ifndef	FASTKAD_H
#define	FASTKAD_H

#include <map>

namespace Kademlia
{
	class CFastKad
	{
	private:
		struct ResponseTimeEntry
		{
			clock_t		m_clkResponseTime;
			clock_t		m_clkLastReferenced;
		};
	
	public:
		CFastKad();
		~CFastKad();
		void AddResponseTime(uint32 uIP, clock_t clkResponseTime);
		void ShutdownCleanup();
		clock_t GetEstMaxResponseTime() const {return m_clkEstResponseTime;}

	private:
		void RecalculateResponseTime();

		static const size_t s_uMaxResponseTimes = 100;
		std::map<uint32, ResponseTimeEntry*> m_mapResponseTimes;

		double	m_fResponseTimeMean;
		double	m_fResponseTimeVariance;
		clock_t	m_clkEstResponseTime;
	};

	extern CFastKad fastKad;
}
#endif	//FASTKAD_H
