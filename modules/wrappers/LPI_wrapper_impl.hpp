#include <stdint.h>
typedef void lpi_data_t;

struct lpiResult {
	uint32_t proto;
	uint32_t category;
};

struct lpiProtocolInfo {
	uint32_t proto;
	uint32_t category;
	char name[256];
};

#ifdef __cplusplus
extern "C" {
#endif
int lpiInitLibrary();
lpi_data_t *lpiCreateFlow();
void lpiFreeFlow(lpi_data_t*);
int lpiAddPacketToFlow(lpi_data_t*, const void*, unsigned short, int dir);
struct lpiResult *lpiGuessProtocol(lpi_data_t*);
void lpiDestroyLibrary();
int lpiGetProtocolCount();
struct lpiProtocolInfo *lpiGetProtocolInfo(int index);
void lpiFreeProtocolInfo(struct lpiProtocolInfo *info);
#ifdef __cplusplus
}
#endif
