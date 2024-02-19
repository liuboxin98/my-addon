const game_delay = require("../build/Release/game_delay.node")


ret = game_delay.nget_nslookup("baidu.com")
console.log("1 >>>", ret)

ret = game_delay.nget_delay("106.75.218.226")
console.log("2 >>>", ret)

/*
#define MIB_IF_TYPE_OTHER               1   其他
#define MIB_IF_TYPE_ETHERNET            6   有线
#define MIB_IF_TYPE_TOKENRING           9   令牌环
#define MIB_IF_TYPE_FDDI                15
#define MIB_IF_TYPE_PPP                 23  拨号
#define MIB_IF_TYPE_LOOPBACK            24
#define MIB_IF_TYPE_SLIP                28
#IF_TYPE_IEEE80211                      71  无线
*/

ret = game_delay.nget_default_network_type();
console.log("3 >>>", ret)


var ping_res = game_delay.nget_gateway_ping_delay();
console.log("4 >>>", ping_res)