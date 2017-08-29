#include "../libnetutil/PacketParser.h"

void FuzzMe(const uint8_t *Data, size_t Size)
{
	PacketParser::parse_packet((const u8 *)Data, Size, false);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	FuzzMe(Data, Size);
	return 0;
}

