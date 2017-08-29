#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct uri {
  char *scheme;
  char *user;
  char *pass;
  char *host;
  char *path;
  int port;
};

extern "C" int parse_uri(const char*, struct uri*);

void FuzzMe(char *Data)
{
	struct uri *u = (struct uri *)malloc(sizeof(struct uri));
	memset(u, 0x00, sizeof(struct uri));
	parse_uri((char *)Data, u);
	//ToDo free subfields if they are in use
	//uri_free(u);
	free(u);
}
	
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	if (Size > 0)
	{
		char *newbuffer = (char *)malloc(Size + 1);
		memcpy(newbuffer, Data, Size);
		newbuffer[Size] = '\0';
		FuzzMe(newbuffer);
		free(newbuffer);
	}
	return 0;
}
