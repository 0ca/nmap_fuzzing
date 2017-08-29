#include "../timing.h"
//#include "../tcpip.h"
#include "../struct_ip.h"
#include "../traceroute.h"

void FuzzMe(const uint8_t *Data, size_t Size)
{
	struct ip *ip = (struct ip *)Data;
	//Ignoring small packets (proccessResp does this validation too)
	if (Size < 20 || Size < (4 * ip->ip_hl) + 4U)
    		return;
	Reply reply;
	//Same check as https://github.com/nmap/nmap/blob/9c7ea727a73527b4ddbae60a359cca4f678e8e0b/traceroute.cc#L1312
	if (ip->ip_v == 4 || ip->ip_v == 6)
	    decode_reply(ip, Size, &reply);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	FuzzMe(Data, Size);
	return 0;
}
