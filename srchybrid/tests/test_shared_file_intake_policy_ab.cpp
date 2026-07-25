#include "../SharedFileIntakePolicy.h"

#include <cstddef>
#include <cstdio>
#include <cwchar>

namespace
{
	constexpr const char* kBaselineCommit =
		"de8e27e2029044d533f7090f173c95856fe4635a";

	wchar_t FoldAscii(wchar_t value) noexcept
	{
		return value >= L'A' && value <= L'Z'
			? static_cast<wchar_t>(value + (L'a' - L'A'))
			: value;
	}

	bool EqualsNoCase(
		const wchar_t* left,
		std::size_t leftLength,
		const wchar_t* right) noexcept
	{
		const std::size_t rightLength = std::wcslen(right);
		if (leftLength != rightLength)
			return false;
		for (std::size_t i = 0; i < leftLength; ++i) {
			if (FoldAscii(left[i]) != FoldAscii(right[i]))
				return false;
		}
		return true;
	}

	bool StartsWithNoCase(const wchar_t* value, const wchar_t* prefix) noexcept
	{
		const std::size_t valueLength = std::wcslen(value);
		const std::size_t prefixLength = std::wcslen(prefix);
		return valueLength >= prefixLength
			&& EqualsNoCase(value, prefixLength, prefix);
	}

	bool EndsWithNoCase(const wchar_t* value, const wchar_t* suffix) noexcept
	{
		const std::size_t valueLength = std::wcslen(value);
		const std::size_t suffixLength = std::wcslen(suffix);
		return valueLength >= suffixLength
			&& EqualsNoCase(
				value + valueLength - suffixLength,
				suffixLength,
				suffix);
	}

	bool EmuleAi152ShouldIgnoreFileName(const wchar_t* value) noexcept
	{
		static const wchar_t* const exactNames[] = {
			L"ehthumbs.db",
			L"desktop.ini",
			L".ds_store",
			L".localized",
			L"icon\r",
			L".directory"
		};
		static const wchar_t* const prefixes[] = {
			L"._",
			L"~$",
			L".nfs",
			L".sb-",
			L".syncthing."
		};
		static const wchar_t* const suffixes[] = {
			L".part",
			L".crdownload",
			L".download",
			L".tmp",
			L".temp",
			L"~"
		};

		const std::size_t valueLength = std::wcslen(value);
		for (const wchar_t* name : exactNames) {
			if (EqualsNoCase(value, valueLength, name))
				return true;
		}
		for (const wchar_t* prefix : prefixes) {
			if (StartsWithNoCase(value, prefix))
				return true;
		}
		for (const wchar_t* suffix : suffixes) {
			if (EndsWithNoCase(value, suffix))
				return true;
		}
		return StartsWithNoCase(value, L"~lock.")
			&& EndsWithNoCase(value, L"#");
	}

	struct CorpusCase
	{
		const wchar_t* name;
		bool unsafe;
	};

	const CorpusCase kCorpus[] = {
		{ L"movie.mkv", false },
		{ L"movie.part1.mkv", false },
		{ L"desktop.ini.backup", false },
		{ L"report.tmp.txt", false },
		{ L"thumbs.db", false },
		{ L"my_node_modules.zip", false },
		{ L"ehthumbs.db", true },
		{ L"DESKTOP.INI", true },
		{ L".DS_STORE", true },
		{ L".localized", true },
		{ L"icon\r", true },
		{ L".directory", true },
		{ L"._movie.mkv", true },
		{ L"~$budget.xlsx", true },
		{ L".nfs123", true },
		{ L".sb-download", true },
		{ L".syncthing.movie.mkv", true },
		{ L"movie.part", true },
		{ L"browser.crdownload", true },
		{ L"download.download", true },
		{ L"scratch.tmp", true },
		{ L"scratch.temp", true },
		{ L"backup~", true },
		{ L"~lock.document.odt#", true },
		{ L"movie.part.met", true },
		{ L"movie.part.met.bak", true },
		{ L"movie.partial", true },
		{ L"movie.opdownload", true },
		{ L"movie.aria2", true },
		{ L"movie.filepart", true },
		{ L"movie.bc!", true }
	};

	struct Metrics
	{
		unsigned falsePositives = 0;
		unsigned falseNegatives = 0;
	};

	template <typename Classifier>
	Metrics Measure(Classifier classifier)
	{
		Metrics metrics;
		for (const CorpusCase& item : kCorpus) {
			const bool rejected = classifier(item.name);
			if (rejected && !item.unsafe)
				++metrics.falsePositives;
			if (!rejected && item.unsafe)
				++metrics.falseNegatives;
		}
		return metrics;
	}
}

int main()
{
	const Metrics baseline = Measure(EmuleAi152ShouldIgnoreFileName);
	const Metrics ese = Measure([](const wchar_t* name) {
		return SharedFileIntakePolicy::ShouldIgnoreFileName(name);
	});

	std::printf(
		"AI-I03 A/B baseline=%s corpus=%zu "
		"ai_fp=%u ai_fn=%u ese_fp=%u ese_fn=%u\n",
		kBaselineCommit,
		sizeof(kCorpus) / sizeof(kCorpus[0]),
		baseline.falsePositives,
		baseline.falseNegatives,
		ese.falsePositives,
		ese.falseNegatives);

	if (ese.falsePositives > baseline.falsePositives)
		return 1;
	if (ese.falseNegatives >= baseline.falseNegatives)
		return 1;
	if (ese.falsePositives != 0 || ese.falseNegatives != 0)
		return 1;

	std::printf("AI-I03 A/B: PASS\n");
	return 0;
}
