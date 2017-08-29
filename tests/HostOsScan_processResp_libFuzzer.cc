#include "../osscan2.h"
#include "../Target.h"
#include "/usr/include/netinet/ip.h"

void FuzzMe(const uint8_t *Data, size_t Size)
{
	struct ip *ip = (struct ip *)Data;
	//Ignoring small packets (proccessResp does this validation too)
	if (Size < 20 || Size < (4 * ip->ip_hl) + 4U)
    		return;
	//We need to modify the data so we need to copy it (libFuzzer requirement)
	ip = (struct ip*)malloc(Size);
	memcpy(ip, Data, Size);
	//This is expected to be a correct value
	ip->ip_len = ntohs(Size);

	Target tg;
	tg.setDeviceNames("eth0", "eth0");
	HostOsScan hos(&tg);
	HostOsScanStats hss(&tg);
	hss.upi.patternbyte = 0x43;
	struct timeval rcvdtime;
	hos.processResp(&hss, ip, Size, &rcvdtime);
	free(ip);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	FuzzMe(Data, Size);
	return 0;
}
