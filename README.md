# Bitcoin Firewall
World's first implementation of connections firewall + intelligent attack detection

Version 1.2.3 - October 14, 2017

Bitcoin Firewall uses a very unique method for detecting potential hard-fork attacks coupled with specific block chain DDoS flooding. All connected nodes/peers are examined by the amount of data they're sending or receiving from a peer with the firewall enabled. If bandwidth usage is greater than the limits set the connecting node is further examined to verify their blockchain start height is within safe limits of the average among all peers connected. Range based blockchain checkpoints that use averages of live blockchain sizes further enhance security by limiting potential attacks known as >51% of distributed hashing power.

Once a potential attack is detected the connected node/peer is forcefully terminated and added to a session blacklist. Configuration options, as well as long-term blacklist storage and future sharing among peers will be implemented during future developments.

# Security features
- Detection of Hard-fork attacks (Dynamic Checkpoint)
- SendFlood protection
- BLACKLIST nodes/peers (Session Ban IP)

# Requirements:
- Bitcoin Core 10 compatible coin
- make

# Installation:
- Download source-code
- Download net.cpp copy into src
- follow instructions for build

# Modification (Live Terminal Debug)
- Edit: net.cpp - Line # 114
- bool Show_DebugOutput = false;    >>>>    bool Show_DebugOutput = true;

# Logging (debug.log)

- 2017-07-28 06:45:31 Firewall - Netflood Detected: *.*.*.*:****
- 2017-07-28 06:45:31 Firewall - Blacklisted: *.*.*.*:****
- 2017-07-28 06:45:31 Firewall - Panic Disconnect: *.*.*.*:****

# Contribute to development
Please donate cryptocoins:

- Bitcoin: 1F4TunADj7BMkYCpWKwsmtxixwdVG9WS1n
- BitConnect: 8XZfQco6HjE7HhyHDmJEubQVKZLSP8jDUs
- Litecoin: Lfo8x4dazSnoJwsXG4KG94r4UeDUCrJE3S
- Peercoin: PJQndzQx8ZT8seHSMAKnLXSSX6muSq9kkF
- Bata: BF7yRP194YfkRG2X3sRjqJWxbYkEMysn65
- Dash: XtL8UPrZnfhwgq5dEJyTgi8MmjcxFM49qx
- Stratis: SiEboTxzWn7XFp49Mi8vZKM5pYYN8RquTg
- Pivx: DBrnFPRsviQKtKGqy1CGVeezVLxWMNDCzx
- Zcoin: a9NvxHohyZ9croSxtxfwBTnrH5gsvnQcU5
- Crypto Bullion: 5hV1b1Z1SowecPPbWtRDLhASKY4qM9ZYpb
- GoldCoin: E3Rw5FP2mUBE5beGaiiWRbPVpqA5yrJhg7
