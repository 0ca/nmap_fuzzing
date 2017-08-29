#include "../nmap_dns.h"

void FuzzMe(const uint8_t *Data, size_t Size)
{
	DNS::Packet p;
	size_t plen = p.parseFromBuffer(Data, Size);	
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	FuzzMe(Data, Size);
	return 0;
}
