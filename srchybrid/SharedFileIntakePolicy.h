// This file is part of eMule eSE.
// Shared-file intake policy kept independent from MFC so startup scans,
// directory notifications and standalone tests use exactly the same rules.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cwchar>

class SharedFileIntakePolicy final
{
public:
	enum class Rejection : std::uint8_t
	{
		None = 0,
		Directory,
		SystemAttribute,
		TemporaryAttribute,
		Empty,
		TooLarge,
		UnsafeName
	};

	struct FileFacts
	{
		bool isDirectory = false;
		bool isSystem = false;
		bool isTemporary = false;
		std::uint64_t size = 0;
	};

	static Rejection ClassifyFile(
		const wchar_t* leafName,
		std::size_t leafNameLength,
		const FileFacts& facts,
		std::uint64_t maximumSize) noexcept
	{
		if (facts.isDirectory)
			return Rejection::Directory;
		if (facts.isSystem)
			return Rejection::SystemAttribute;
		if (facts.isTemporary)
			return Rejection::TemporaryAttribute;
		if (facts.size == 0)
			return Rejection::Empty;
		if (facts.size > maximumSize)
			return Rejection::TooLarge;
		if (ShouldIgnoreFileName(leafName, leafNameLength))
			return Rejection::UnsafeName;
		return Rejection::None;
	}

	static Rejection ClassifyFile(
		const wchar_t* leafName,
		const FileFacts& facts,
		std::uint64_t maximumSize) noexcept
	{
		return ClassifyFile(
			leafName,
			leafName != nullptr ? std::wcslen(leafName) : 0,
			facts,
			maximumSize);
	}

	static bool ShouldIgnoreFileName(
		const wchar_t* leafName,
		std::size_t leafNameLength) noexcept
	{
		if (leafName == nullptr || leafNameLength == 0)
			return false;

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
			L".part.met",
			L".part.met.bak",
			L".crdownload",
			L".download",
			L".partial",
			L".opdownload",
			L".aria2",
			L".filepart",
			L".bc!",
			L".tmp",
			L".temp",
			L"~"
		};

		for (const wchar_t* value : exactNames) {
			if (EqualsIgnoreAsciiCase(
					leafName,
					leafNameLength,
					value,
					std::wcslen(value)))
				return true;
		}
		for (const wchar_t* value : prefixes) {
			if (StartsWithIgnoreAsciiCase(
					leafName,
					leafNameLength,
					value,
					std::wcslen(value)))
				return true;
		}
		for (const wchar_t* value : suffixes) {
			if (EndsWithIgnoreAsciiCase(
					leafName,
					leafNameLength,
					value,
					std::wcslen(value)))
				return true;
		}

		return StartsWithIgnoreAsciiCase(
				leafName, leafNameLength, L"~lock.", 6)
			&& EndsWithIgnoreAsciiCase(
				leafName, leafNameLength, L"#", 1);
	}

	static bool ShouldIgnoreFileName(const wchar_t* leafName) noexcept
	{
		return ShouldIgnoreFileName(
			leafName,
			leafName != nullptr ? std::wcslen(leafName) : 0);
	}

	static bool ShouldIgnoreDirectoryName(
		const wchar_t* leafName,
		std::size_t leafNameLength) noexcept
	{
		if (leafName == nullptr || leafNameLength == 0)
			return false;

		static const wchar_t* const exactNames[] = {
			L".fseventsd",
			L".spotlight-v100",
			L".temporaryitems",
			L".trashes",
			L"$recycle.bin",
			L"system volume information",
			L".git",
			L".svn",
			L".hg",
			L"cvs",
			L".vs",
			L".idea",
			L"node_modules"
		};
		static const wchar_t* const prefixes[] = {
			L"._",
			L".nfs",
			L".sb-",
			L".syncthing."
		};

		for (const wchar_t* value : exactNames) {
			if (EqualsIgnoreAsciiCase(
					leafName,
					leafNameLength,
					value,
					std::wcslen(value)))
				return true;
		}
		for (const wchar_t* value : prefixes) {
			if (StartsWithIgnoreAsciiCase(
					leafName,
					leafNameLength,
					value,
					std::wcslen(value)))
				return true;
		}
		return false;
	}

	static bool ShouldIgnoreDirectoryName(const wchar_t* leafName) noexcept
	{
		return ShouldIgnoreDirectoryName(
			leafName,
			leafName != nullptr ? std::wcslen(leafName) : 0);
	}

private:
	static constexpr wchar_t FoldAscii(wchar_t value) noexcept
	{
		return value >= L'A' && value <= L'Z'
			? static_cast<wchar_t>(value + (L'a' - L'A'))
			: value;
	}

	static bool EqualsIgnoreAsciiCase(
		const wchar_t* left,
		std::size_t leftLength,
		const wchar_t* right,
		std::size_t rightLength) noexcept
	{
		if (leftLength != rightLength)
			return false;
		for (std::size_t i = 0; i < leftLength; ++i) {
			if (FoldAscii(left[i]) != FoldAscii(right[i]))
				return false;
		}
		return true;
	}

	static bool StartsWithIgnoreAsciiCase(
		const wchar_t* value,
		std::size_t valueLength,
		const wchar_t* prefix,
		std::size_t prefixLength) noexcept
	{
		return valueLength >= prefixLength
			&& EqualsIgnoreAsciiCase(
				value, prefixLength, prefix, prefixLength);
	}

	static bool EndsWithIgnoreAsciiCase(
		const wchar_t* value,
		std::size_t valueLength,
		const wchar_t* suffix,
		std::size_t suffixLength) noexcept
	{
		return valueLength >= suffixLength
			&& EqualsIgnoreAsciiCase(
				value + (valueLength - suffixLength),
				suffixLength,
				suffix,
				suffixLength);
	}
};
