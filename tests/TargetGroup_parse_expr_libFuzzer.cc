#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include "../TargetGroup.h"

void FuzzMe(const char *Data)
{
	TargetGroup tg;
	tg.parse_expr(Data, AF_INET);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	if (Size > 0)
	{
		char * new_buffer = (char *)malloc(Size + 1);
		memcpy(new_buffer, Data, Size);
		new_buffer[Size] = '\0';
		FuzzMe(new_buffer);
		free(new_buffer);
	}
	return 0;
}
