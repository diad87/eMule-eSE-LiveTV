#include "../SharedFileIntakePolicy.h"

#include <cstdint>
#include <cstdio>

static int failures = 0;

#define CHECK(condition, message) do { \
	if (!(condition)) { \
		std::printf("FAIL: %s\n", message); \
		++failures; \
	} \
} while (0)

static SharedFileIntakePolicy::Rejection Classify(
	const wchar_t* name,
	std::uint64_t size = 1,
	bool directory = false,
	bool system = false,
	bool temporary = false)
{
	SharedFileIntakePolicy::FileFacts facts;
	facts.isDirectory = directory;
	facts.isSystem = system;
	facts.isTemporary = temporary;
	facts.size = size;
	return SharedFileIntakePolicy::ClassifyFile(name, facts, 1000);
}

int main()
{
	using Rejection = SharedFileIntakePolicy::Rejection;

	CHECK(Classify(L"movie.mkv") == Rejection::None,
		"a normal media file must be accepted");
	CHECK(Classify(L"movie.part1.mkv") == Rejection::None,
		"part inside a valid filename must not be treated as a suffix");
	CHECK(Classify(L"desktop.ini.backup") == Rejection::None,
		"an exact ignored name with a valid suffix must be accepted");
	CHECK(Classify(L"report.tmp.txt") == Rejection::None,
		"a temporary marker inside a valid filename must be accepted");

	CHECK(Classify(L"THUMBS.DB") == Rejection::None,
		"filename policy must leave content validation of thumbs.db to IsThumbsDb");
	CHECK(Classify(L"DESKTOP.INI") == Rejection::UnsafeName,
		"exact ignored names must be case insensitive");
	CHECK(Classify(L"movie.PART") == Rejection::UnsafeName,
		"eMule part files must be rejected");
	CHECK(Classify(L"movie.part.met.bak") == Rejection::UnsafeName,
		"eMule part metadata backups must be rejected");
	CHECK(Classify(L"browser.CRDOWNLOAD") == Rejection::UnsafeName,
		"incomplete browser downloads must be rejected");
	CHECK(Classify(L"download.aria2") == Rejection::UnsafeName,
		"incomplete aria2 downloads must be rejected");
	CHECK(Classify(L"download.partial") == Rejection::UnsafeName,
		"incomplete generic downloads must be rejected");
	CHECK(Classify(L"~$budget.xlsx") == Rejection::UnsafeName,
		"office lock files must be rejected");
	CHECK(Classify(L"~lock.document.odt#") == Rejection::UnsafeName,
		"LibreOffice lock files must be rejected");
	CHECK(Classify(L".syncthing.movie.mkv.tmp") == Rejection::UnsafeName,
		"sync temporary files must be rejected");

	CHECK(Classify(L"folder", 1, true) == Rejection::Directory,
		"directories must not enter the file pipeline");
	CHECK(Classify(L"system.dat", 1, false, true) == Rejection::SystemAttribute,
		"system files must be rejected");
	CHECK(Classify(L"temporary.dat", 1, false, false, true) == Rejection::TemporaryAttribute,
		"temporary-attributed files must be rejected");
	CHECK(Classify(L"empty.bin", 0) == Rejection::Empty,
		"empty files must be rejected");
	CHECK(Classify(L"huge.bin", 1001) == Rejection::TooLarge,
		"files above the protocol limit must be rejected");

	CHECK(SharedFileIntakePolicy::ShouldIgnoreDirectoryName(L".GIT"),
		"VCS directories must be rejected case insensitively");
	CHECK(SharedFileIntakePolicy::ShouldIgnoreDirectoryName(L"node_modules"),
		"dependency trees must be rejected from recursive sharing");
	CHECK(SharedFileIntakePolicy::ShouldIgnoreDirectoryName(L"$Recycle.Bin"),
		"recycle bins must be rejected from recursive sharing");
	CHECK(!SharedFileIntakePolicy::ShouldIgnoreDirectoryName(L"git-mirror"),
		"similar but valid directory names must be accepted");
	CHECK(!SharedFileIntakePolicy::ShouldIgnoreDirectoryName(L"my_node_modules"),
		"directory ignores must not use substring matching");

	if (failures != 0)
		return 1;
	std::printf("shared file intake policy: PASS\n");
	return 0;
}
