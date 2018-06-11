// Copyright (c) 2009-2017 The Bitcoin Core developers
// Copyright (c) 2018 FXTC developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>

#include <chainparams.h>
#include <clientversion.h>
#include <core_io.h>
#include <validation.h>
#include <net.h>
#include <net_processing.h>
#include <netbase.h>
#include <policy/policy.h>
#include <rpc/protocol.h>
#include <sync.h>
#include <timedata.h>
#include <ui_interface.h>
#include <util.h>
#include <utilstrencodings.h>
#include <version.h>
#include <warnings.h>

#include <univalue.h>

extern int CountStringArray(std::string *ArrayName);
extern int CountIntArray(int *ArrayName);

inline const char * const BoolToString(bool b)
{
  return b ? "true" : "false";
}

UniValue getconnectioncount(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getconnectioncount\n"
            "\nReturns the number of connections to other nodes.\n"
            "\nResult:\n"
            "n          (numeric) The connection count\n"
            "\nExamples:\n"
            + HelpExampleCli("getconnectioncount", "")
            + HelpExampleRpc("getconnectioncount", "")
        );

    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    return (int)g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL);
}

UniValue ping(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "ping\n"
            "\nRequests that a ping be sent to all other nodes, to measure ping time.\n"
            "Results provided in getpeerinfo, pingtime and pingwait fields are decimal seconds.\n"
            "Ping command is handled in queue with all other commands, so it measures processing backlog, not just network ping.\n"
            "\nExamples:\n"
            + HelpExampleCli("ping", "")
            + HelpExampleRpc("ping", "")
        );

    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    // Request that each node send a ping during next message processing pass
    g_connman->ForEachNode([](CNode* pnode) {
        pnode->fPingQueued = true;
    });
    return NullUniValue;
}

UniValue getpeerinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getpeerinfo\n"
            "\nReturns data about each connected network node as a json array of objects.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"id\": n,                   (numeric) Peer index\n"
            "    \"addr\":\"host:port\",      (string) The IP address and port of the peer\n"
            "    \"addrbind\":\"ip:port\",    (string) Bind address of the connection to the peer\n"
            "    \"addrlocal\":\"ip:port\",   (string) Local address as reported by the peer\n"
            "    \"services\":\"xxxxxxxxxxxxxxxx\",   (string) The services offered\n"
            "    \"relaytxes\":true|false,    (boolean) Whether peer has asked us to relay transactions to it\n"
            "    \"lastsend\": ttt,           (numeric) The time in seconds since epoch (Jan 1 1970 GMT) of the last send\n"
            "    \"lastrecv\": ttt,           (numeric) The time in seconds since epoch (Jan 1 1970 GMT) of the last receive\n"
            "    \"bytessent\": n,            (numeric) The total bytes sent\n"
            "    \"bytesrecv\": n,            (numeric) The total bytes received\n"
            "    \"conntime\": ttt,           (numeric) The connection time in seconds since epoch (Jan 1 1970 GMT)\n"
            "    \"timeoffset\": ttt,         (numeric) The time offset in seconds\n"
            "    \"pingtime\": n,             (numeric) ping time (if available)\n"
            "    \"minping\": n,              (numeric) minimum observed ping time (if any at all)\n"
            "    \"pingwait\": n,             (numeric) ping wait (if non-zero)\n"
            "    \"version\": v,              (numeric) The peer version, such as 70001\n"
            "    \"subver\": \"/Satoshi:0.8.5/\",  (string) The string version\n"
            "    \"inbound\": true|false,     (boolean) Inbound (true) or Outbound (false)\n"
            "    \"addnode\": true|false,     (boolean) Whether connection was due to addnode/-connect or if it was an automatic/inbound connection\n"
            "    \"startingheight\": n,       (numeric) The starting height (block) of the peer\n"
            "    \"banscore\": n,             (numeric) The ban score\n"
            "    \"synced_headers\": n,       (numeric) The last header we have in common with this peer\n"
            "    \"synced_blocks\": n,        (numeric) The last block we have in common with this peer\n"
            "    \"inflight\": [\n"
            "       n,                        (numeric) The heights of blocks we're currently asking from this peer\n"
            "       ...\n"
            "    ],\n"
            "    \"whitelisted\": true|false, (boolean) Whether the peer is whitelisted\n"
            "    \"bytessent_per_msg\": {\n"
            "       \"addr\": n,              (numeric) The total bytes sent aggregated by message type\n"
            "       ...\n"
            "    },\n"
            "    \"bytesrecv_per_msg\": {\n"
            "       \"addr\": n,              (numeric) The total bytes received aggregated by message type\n"
            "       ...\n"
            "    }\n"
            "  }\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getpeerinfo", "")
            + HelpExampleRpc("getpeerinfo", "")
        );

    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    std::vector<CNodeStats> vstats;
    g_connman->GetNodeStats(vstats);

    UniValue ret(UniValue::VARR);

    for (const CNodeStats& stats : vstats) {
        UniValue obj(UniValue::VOBJ);
        CNodeStateStats statestats;
        bool fStateStats = GetNodeStateStats(stats.nodeid, statestats);
        obj.push_back(Pair("id", stats.nodeid));
        obj.push_back(Pair("addr", stats.addrName));
        if (!(stats.addrLocal.empty()))
            obj.push_back(Pair("addrlocal", stats.addrLocal));
        if (stats.addrBind.IsValid())
            obj.push_back(Pair("addrbind", stats.addrBind.ToString()));
        obj.push_back(Pair("services", strprintf("%016x", stats.nServices)));
        obj.push_back(Pair("relaytxes", stats.fRelayTxes));
        obj.push_back(Pair("lastsend", stats.nLastSend));
        obj.push_back(Pair("lastrecv", stats.nLastRecv));
        obj.push_back(Pair("bytessent", stats.nSendBytes));
        obj.push_back(Pair("bytesrecv", stats.nRecvBytes));
        obj.push_back(Pair("conntime", stats.nTimeConnected));
        obj.push_back(Pair("timeoffset", stats.nTimeOffset));
        if (stats.dPingTime > 0.0)
            obj.push_back(Pair("pingtime", stats.dPingTime));
        if (stats.dMinPing < static_cast<double>(std::numeric_limits<int64_t>::max())/1e6)
            obj.push_back(Pair("minping", stats.dMinPing));
        if (stats.dPingWait > 0.0)
            obj.push_back(Pair("pingwait", stats.dPingWait));
        obj.push_back(Pair("version", stats.nVersion));
        // Use the sanitized form of subver here, to avoid tricksy remote peers from
        // corrupting or modifying the JSON output by putting special characters in
        // their ver message.
        obj.push_back(Pair("subver", stats.cleanSubVer));
        obj.push_back(Pair("inbound", stats.fInbound));
        obj.push_back(Pair("addnode", stats.m_manual_connection));
        obj.push_back(Pair("startingheight", stats.nStartingHeight));
        if (fStateStats) {
            obj.push_back(Pair("banscore", statestats.nMisbehavior));
            obj.push_back(Pair("synced_headers", statestats.nSyncHeight));
            obj.push_back(Pair("synced_blocks", statestats.nCommonHeight));
            UniValue heights(UniValue::VARR);
            for (int height : statestats.vHeightInFlight) {
                heights.push_back(height);
            }
            obj.push_back(Pair("inflight", heights));
        }
        obj.push_back(Pair("whitelisted", stats.fWhitelisted));

        UniValue sendPerMsgCmd(UniValue::VOBJ);
        for (const mapMsgCmdSize::value_type &i : stats.mapSendBytesPerMsgCmd) {
            if (i.second > 0)
                sendPerMsgCmd.push_back(Pair(i.first, i.second));
        }
        obj.push_back(Pair("bytessent_per_msg", sendPerMsgCmd));

        UniValue recvPerMsgCmd(UniValue::VOBJ);
        for (const mapMsgCmdSize::value_type &i : stats.mapRecvBytesPerMsgCmd) {
            if (i.second > 0)
                recvPerMsgCmd.push_back(Pair(i.first, i.second));
        }
        obj.push_back(Pair("bytesrecv_per_msg", recvPerMsgCmd));

        ret.push_back(obj);
    }

    return ret;
}

UniValue addnode(const JSONRPCRequest& request)
{
    std::string strCommand;
    if (!request.params[1].isNull())
        strCommand = request.params[1].get_str();
    if (request.fHelp || request.params.size() != 2 ||
        (strCommand != "onetry" && strCommand != "add" && strCommand != "remove"))
        throw std::runtime_error(
            "addnode \"node\" \"add|remove|onetry\"\n"
            "\nAttempts to add or remove a node from the addnode list.\n"
            "Or try a connection to a node once.\n"
            "Nodes added using addnode (or -connect) are protected from DoS disconnection and are not required to be\n"
            "full nodes/support SegWit as other outbound peers are (though such peers will not be synced from).\n"
            "\nArguments:\n"
            "1. \"node\"     (string, required) The node (see getpeerinfo for nodes)\n"
            "2. \"command\"  (string, required) 'add' to add a node to the list, 'remove' to remove a node from the list, 'onetry' to try a connection to the node once\n"
            "\nExamples:\n"
            + HelpExampleCli("addnode", "\"192.168.0.6:8333\" \"onetry\"")
            + HelpExampleRpc("addnode", "\"192.168.0.6:8333\", \"onetry\"")
        );

    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    std::string strNode = request.params[0].get_str();

    if (strCommand == "onetry")
    {
        CAddress addr;
        g_connman->OpenNetworkConnection(addr, false, nullptr, strNode.c_str(), false, false, true);
        return NullUniValue;
    }

    if (strCommand == "add")
    {
        if(!g_connman->AddNode(strNode))
            throw JSONRPCError(RPC_CLIENT_NODE_ALREADY_ADDED, "Error: Node already added");
    }
    else if(strCommand == "remove")
    {
        if(!g_connman->RemoveAddedNode(strNode))
            throw JSONRPCError(RPC_CLIENT_NODE_NOT_ADDED, "Error: Node has not been added.");
    }

    return NullUniValue;
}

UniValue disconnectnode(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0 || request.params.size() >= 3)
        throw std::runtime_error(
            "disconnectnode \"[address]\" [nodeid]\n"
            "\nImmediately disconnects from the specified peer node.\n"
            "\nStrictly one out of 'address' and 'nodeid' can be provided to identify the node.\n"
            "\nTo disconnect by nodeid, either set 'address' to the empty string, or call using the named 'nodeid' argument only.\n"
            "\nArguments:\n"
            "1. \"address\"     (string, optional) The IP address/port of the node\n"
            "2. \"nodeid\"      (number, optional) The node ID (see getpeerinfo for node IDs)\n"
            "\nExamples:\n"
            + HelpExampleCli("disconnectnode", "\"192.168.0.6:8333\"")
            + HelpExampleCli("disconnectnode", "\"\" 1")
            + HelpExampleRpc("disconnectnode", "\"192.168.0.6:8333\"")
            + HelpExampleRpc("disconnectnode", "\"\", 1")
        );

    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    bool success;
    const UniValue &address_arg = request.params[0];
    const UniValue &id_arg = request.params[1];

    if (!address_arg.isNull() && id_arg.isNull()) {
        /* handle disconnect-by-address */
        success = g_connman->DisconnectNode(address_arg.get_str());
    } else if (!id_arg.isNull() && (address_arg.isNull() || (address_arg.isStr() && address_arg.get_str().empty()))) {
        /* handle disconnect-by-id */
        NodeId nodeid = (NodeId) id_arg.get_int64();
        success = g_connman->DisconnectNode(nodeid);
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Only one of address and nodeid should be provided.");
    }

    if (!success) {
        throw JSONRPCError(RPC_CLIENT_NODE_NOT_CONNECTED, "Node not found in connected nodes");
    }

    return NullUniValue;
}

UniValue getaddednodeinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "getaddednodeinfo ( \"node\" )\n"
            "\nReturns information about the given added node, or all added nodes\n"
            "(note that onetry addnodes are not listed here)\n"
            "\nArguments:\n"
            "1. \"node\"   (string, optional) If provided, return information about this specific node, otherwise all nodes are returned.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"addednode\" : \"192.168.0.201\",   (string) The node IP address or name (as provided to addnode)\n"
            "    \"connected\" : true|false,          (boolean) If connected\n"
            "    \"addresses\" : [                    (list of objects) Only when connected = true\n"
            "       {\n"
            "         \"address\" : \"192.168.0.201:8333\",  (string) The fxtcoin server IP and port we're connected to\n"
            "         \"connected\" : \"outbound\"           (string) connection, inbound or outbound\n"
            "       }\n"
            "     ]\n"
            "  }\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddednodeinfo", "\"192.168.0.201\"")
            + HelpExampleRpc("getaddednodeinfo", "\"192.168.0.201\"")
        );

    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    std::vector<AddedNodeInfo> vInfo = g_connman->GetAddedNodeInfo();

    if (!request.params[0].isNull()) {
        bool found = false;
        for (const AddedNodeInfo& info : vInfo) {
            if (info.strAddedNode == request.params[0].get_str()) {
                vInfo.assign(1, info);
                found = true;
                break;
            }
        }
        if (!found) {
            throw JSONRPCError(RPC_CLIENT_NODE_NOT_ADDED, "Error: Node has not been added.");
        }
    }

    UniValue ret(UniValue::VARR);

    for (const AddedNodeInfo& info : vInfo) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("addednode", info.strAddedNode));
        obj.push_back(Pair("connected", info.fConnected));
        UniValue addresses(UniValue::VARR);
        if (info.fConnected) {
            UniValue address(UniValue::VOBJ);
            address.push_back(Pair("address", info.resolvedAddress.ToString()));
            address.push_back(Pair("connected", info.fInbound ? "inbound" : "outbound"));
            addresses.push_back(address);
        }
        obj.push_back(Pair("addresses", addresses));
        ret.push_back(obj);
    }

    return ret;
}

UniValue getnettotals(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 0)
        throw std::runtime_error(
            "getnettotals\n"
            "\nReturns information about network traffic, including bytes in, bytes out,\n"
            "and current time.\n"
            "\nResult:\n"
            "{\n"
            "  \"totalbytesrecv\": n,   (numeric) Total bytes received\n"
            "  \"totalbytessent\": n,   (numeric) Total bytes sent\n"
            "  \"timemillis\": t,       (numeric) Current UNIX time in milliseconds\n"
            "  \"uploadtarget\":\n"
            "  {\n"
            "    \"timeframe\": n,                         (numeric) Length of the measuring timeframe in seconds\n"
            "    \"target\": n,                            (numeric) Target in bytes\n"
            "    \"target_reached\": true|false,           (boolean) True if target is reached\n"
            "    \"serve_historical_blocks\": true|false,  (boolean) True if serving historical blocks\n"
            "    \"bytes_left_in_cycle\": t,               (numeric) Bytes left in current time cycle\n"
            "    \"time_left_in_cycle\": t                 (numeric) Seconds left in current time cycle\n"
            "  }\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getnettotals", "")
            + HelpExampleRpc("getnettotals", "")
       );
    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("totalbytesrecv", g_connman->GetTotalBytesRecv()));
    obj.push_back(Pair("totalbytessent", g_connman->GetTotalBytesSent()));
    obj.push_back(Pair("timemillis", GetTimeMillis()));

    UniValue outboundLimit(UniValue::VOBJ);
    outboundLimit.push_back(Pair("timeframe", g_connman->GetMaxOutboundTimeframe()));
    outboundLimit.push_back(Pair("target", g_connman->GetMaxOutboundTarget()));
    outboundLimit.push_back(Pair("target_reached", g_connman->OutboundTargetReached(false)));
    outboundLimit.push_back(Pair("serve_historical_blocks", !g_connman->OutboundTargetReached(true)));
    outboundLimit.push_back(Pair("bytes_left_in_cycle", g_connman->GetOutboundTargetBytesLeft()));
    outboundLimit.push_back(Pair("time_left_in_cycle", g_connman->GetMaxOutboundTimeLeftInCycle()));
    obj.push_back(Pair("uploadtarget", outboundLimit));
    return obj;
}

static UniValue GetNetworksInfo()
{
    UniValue networks(UniValue::VARR);
    for(int n=0; n<NET_MAX; ++n)
    {
        enum Network network = static_cast<enum Network>(n);
        if(network == NET_UNROUTABLE || network == NET_INTERNAL)
            continue;
        proxyType proxy;
        UniValue obj(UniValue::VOBJ);
        GetProxy(network, proxy);
        obj.push_back(Pair("name", GetNetworkName(network)));
        obj.push_back(Pair("limited", IsLimited(network)));
        obj.push_back(Pair("reachable", IsReachable(network)));
        obj.push_back(Pair("proxy", proxy.IsValid() ? proxy.proxy.ToStringIPPort() : std::string()));
        obj.push_back(Pair("proxy_randomize_credentials", proxy.randomize_credentials));
        networks.push_back(obj);
    }
    return networks;
}

UniValue getnetworkinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getnetworkinfo\n"
            "Returns an object containing various state info regarding P2P networking.\n"
            "\nResult:\n"
            "{\n"
            "  \"version\": xxxxx,                      (numeric) the server version\n"
            "  \"subversion\": \"/Satoshi:x.x.x/\",     (string) the server subversion string\n"
            "  \"protocolversion\": xxxxx,              (numeric) the protocol version\n"
            "  \"localservices\": \"xxxxxxxxxxxxxxxx\", (string) the services we offer to the network\n"
            "  \"localrelay\": true|false,              (bool) true if transaction relay is requested from peers\n"
            "  \"timeoffset\": xxxxx,                   (numeric) the time offset\n"
            "  \"connections\": xxxxx,                  (numeric) the number of connections\n"
            "  \"networkactive\": true|false,           (bool) whether p2p networking is enabled\n"
            "  \"networks\": [                          (array) information per network\n"
            "  {\n"
            "    \"name\": \"xxx\",                     (string) network (ipv4, ipv6 or onion)\n"
            "    \"limited\": true|false,               (boolean) is the network limited using -onlynet?\n"
            "    \"reachable\": true|false,             (boolean) is the network reachable?\n"
            "    \"proxy\": \"host:port\"               (string) the proxy that is used for this network, or empty if none\n"
            "    \"proxy_randomize_credentials\": true|false,  (string) Whether randomized credentials are used\n"
            "  }\n"
            "  ,...\n"
            "  ],\n"
            "  \"relayfee\": x.xxxxxxxx,                (numeric) minimum relay fee for transactions in " + CURRENCY_UNIT + "/kB\n"
            "  \"incrementalfee\": x.xxxxxxxx,          (numeric) minimum fee increment for mempool limiting or BIP 125 replacement in " + CURRENCY_UNIT + "/kB\n"
            "  \"localaddresses\": [                    (array) list of local addresses\n"
            "  {\n"
            "    \"address\": \"xxxx\",                 (string) network address\n"
            "    \"port\": xxx,                         (numeric) network port\n"
            "    \"score\": xxx                         (numeric) relative score\n"
            "  }\n"
            "  ,...\n"
            "  ]\n"
            "  \"warnings\": \"...\"                    (string) any network and blockchain warnings\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getnetworkinfo", "")
            + HelpExampleRpc("getnetworkinfo", "")
        );

    LOCK(cs_main);
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version",       CLIENT_VERSION));
    obj.push_back(Pair("subversion",    strSubVersion));
    obj.push_back(Pair("protocolversion",PROTOCOL_VERSION));
    if(g_connman)
        obj.push_back(Pair("localservices", strprintf("%016x", g_connman->GetLocalServices())));
    obj.push_back(Pair("localrelay",     fRelayTxes));
    obj.push_back(Pair("timeoffset",    GetTimeOffset()));
    if (g_connman) {
        obj.push_back(Pair("networkactive", g_connman->GetNetworkActive()));
        obj.push_back(Pair("connections",   (int)g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL)));
    }
    obj.push_back(Pair("networks",      GetNetworksInfo()));
    obj.push_back(Pair("relayfee",      ValueFromAmount(::minRelayTxFee.GetFeePerK())));
    obj.push_back(Pair("incrementalfee", ValueFromAmount(::incrementalRelayFee.GetFeePerK())));
    UniValue localAddresses(UniValue::VARR);
    {
        LOCK(cs_mapLocalHost);
        for (const std::pair<CNetAddr, LocalServiceInfo> &item : mapLocalHost)
        {
            UniValue rec(UniValue::VOBJ);
            rec.push_back(Pair("address", item.first.ToString()));
            rec.push_back(Pair("port", item.second.nPort));
            rec.push_back(Pair("score", item.second.nScore));
            localAddresses.push_back(rec);
        }
    }
    obj.push_back(Pair("localaddresses", localAddresses));
    obj.push_back(Pair("warnings",       GetWarnings("statusbar")));
    return obj;
}

UniValue setban(const JSONRPCRequest& request)
{
    std::string strCommand;
    if (!request.params[1].isNull())
        strCommand = request.params[1].get_str();
    if (request.fHelp || request.params.size() < 2 ||
        (strCommand != "add" && strCommand != "remove"))
        throw std::runtime_error(
                            "setban \"subnet\" \"add|remove\" (bantime) (absolute)\n"
                            "\nAttempts to add or remove an IP/Subnet from the banned list.\n"
                            "\nArguments:\n"
                            "1. \"subnet\"       (string, required) The IP/Subnet (see getpeerinfo for nodes IP) with an optional netmask (default is /32 = single IP)\n"
                            "2. \"command\"      (string, required) 'add' to add an IP/Subnet to the list, 'remove' to remove an IP/Subnet from the list\n"
                            "3. \"bantime\"      (numeric, optional) time in seconds how long (or until when if [absolute] is set) the IP is banned (0 or empty means using the default time of 24h which can also be overwritten by the -bantime startup argument)\n"
                            "4. \"absolute\"     (boolean, optional) If set, the bantime must be an absolute timestamp in seconds since epoch (Jan 1 1970 GMT)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("setban", "\"192.168.0.6\" \"add\" 86400")
                            + HelpExampleCli("setban", "\"192.168.0.0/24\" \"add\"")
                            + HelpExampleRpc("setban", "\"192.168.0.6\", \"add\", 86400")
                            );
    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    CSubNet subNet;
    CNetAddr netAddr;
    bool isSubnet = false;

    if (request.params[0].get_str().find('/') != std::string::npos)
        isSubnet = true;

    if (!isSubnet) {
        CNetAddr resolved;
        LookupHost(request.params[0].get_str().c_str(), resolved, false);
        netAddr = resolved;
    }
    else
        LookupSubNet(request.params[0].get_str().c_str(), subNet);

    if (! (isSubnet ? subNet.IsValid() : netAddr.IsValid()) )
        throw JSONRPCError(RPC_CLIENT_INVALID_IP_OR_SUBNET, "Error: Invalid IP/Subnet");

    if (strCommand == "add")
    {
        if (isSubnet ? g_connman->IsBanned(subNet) : g_connman->IsBanned(netAddr))
            throw JSONRPCError(RPC_CLIENT_NODE_ALREADY_ADDED, "Error: IP/Subnet already banned");

        int64_t banTime = 0; //use standard bantime if not specified
        if (!request.params[2].isNull())
            banTime = request.params[2].get_int64();

        bool absolute = false;
        if (request.params[3].isTrue())
            absolute = true;

        isSubnet ? g_connman->Ban(subNet, BanReasonManuallyAdded, banTime, absolute) : g_connman->Ban(netAddr, BanReasonManuallyAdded, banTime, absolute);
    }
    else if(strCommand == "remove")
    {
        if (!( isSubnet ? g_connman->Unban(subNet) : g_connman->Unban(netAddr) ))
            throw JSONRPCError(RPC_CLIENT_INVALID_IP_OR_SUBNET, "Error: Unban failed. Requested address/subnet was not previously banned.");
    }
    return NullUniValue;
}

UniValue listbanned(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
                            "listbanned\n"
                            "\nList all banned IPs/Subnets.\n"
                            "\nExamples:\n"
                            + HelpExampleCli("listbanned", "")
                            + HelpExampleRpc("listbanned", "")
                            );

    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    banmap_t banMap;
    g_connman->GetBanned(banMap);

    UniValue bannedAddresses(UniValue::VARR);
    for (const auto& entry : banMap)
    {
        const CBanEntry& banEntry = entry.second;
        UniValue rec(UniValue::VOBJ);
        rec.push_back(Pair("address", entry.first.ToString()));
        rec.push_back(Pair("banned_until", banEntry.nBanUntil));
        rec.push_back(Pair("ban_created", banEntry.nCreateTime));
        rec.push_back(Pair("ban_reason", banEntry.banReasonToString()));

        bannedAddresses.push_back(rec);
    }

    return bannedAddresses;
}

UniValue clearbanned(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
                            "clearbanned\n"
                            "\nClear all banned IPs.\n"
                            "\nExamples:\n"
                            + HelpExampleCli("clearbanned", "")
                            + HelpExampleRpc("clearbanned", "")
                            );
    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    g_connman->ClearBanned();

    return NullUniValue;
}

UniValue setnetworkactive(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "setnetworkactive true|false\n"
            "\nDisable/enable all p2p network activity.\n"
            "\nArguments:\n"
            "1. \"state\"        (boolean, required) true to enable networking, false to disable\n"
        );
    }

    if (!g_connman) {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    }

    g_connman->SetNetworkActive(request.params[0].get_bool());

    return g_connman->GetNetworkActive();
}


UniValue firewallstatus(const JSONRPCRequest& request)
{
    std::string strCommand = "true";
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
                            "firewallstatus \"\n"
                            "\nGet the status of Bitcoin Firewall.\n"
                            );


    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("enabled", BoolToString(FIREWALL_ENABLED)));
    result.push_back(Pair("clear-banlist", BoolToString(FIREWALL_CLEAR_BANS)));
    result.push_back(Pair("live-debug", BoolToString(FIREWALL_LIVE_DEBUG)));
    result.push_back(Pair("live-debug-exam", BoolToString(FIREWALL_LIVEDEBUG_EXAM)));
    result.push_back(Pair("live-debug-bans", BoolToString(FIREWALL_LIVEDEBUG_BANS)));
    result.push_back(Pair("live-debug-disconnect", BoolToString(FIREWALL_LIVEDEBUG_DISCONNECT)));
    result.push_back(Pair("live-debug-bandwidthabuse", BoolToString(FIREWALL_LIVEDEBUG_BANDWIDTHABUSE)));
    result.push_back(Pair("live-debug-nofalsepositive", BoolToString(FIREWALL_LIVEDEBUG_NOFALSEPOSITIVE)));
    result.push_back(Pair("live-debug-invalidwallet", BoolToString(FIREWALL_LIVEDEBUG_INVALIDWALLET)));
    result.push_back(Pair("live-debug-forkedwallet", BoolToString(FIREWALL_LIVEDEBUG_FORKEDWALLET)));
    result.push_back(Pair("live-debug-floodingwallet", BoolToString(FIREWALL_LIVEDEBUG_FLOODINGWALLET)));
    result.push_back(Pair("detect-bandwidthabuse", BoolToString(FIREWALL_DETECT_BANDWIDTHABUSE)));
    result.push_back(Pair("nofalsepositive", BoolToString(FIREWALL_NOFALSEPOSITIVE_BANDWIDTHABUSE)));
    result.push_back(Pair("detect-invalidwallet", BoolToString(FIREWALL_DETECT_INVALIDWALLET)));
    result.push_back(Pair("detect-forkedwallet", BoolToString(FIREWALL_DETECT_FORKEDWALLET)));
    result.push_back(Pair("detect-floodingwallet", BoolToString(FIREWALL_DETECT_FLOODINGWALLET)));
    result.push_back(Pair("ban-bandwidthabuse", BoolToString(FIREWALL_BAN_BANDWIDTHABUSE)));
    result.push_back(Pair("ban-invalidwallet", BoolToString(FIREWALL_BAN_INVALIDWALLET)));
    result.push_back(Pair("ban-forkedwallet", BoolToString(FIREWALL_BAN_FORKEDWALLET)));
    result.push_back(Pair("ban-floodingwallet", BoolToString(FIREWALL_BAN_FLOODINGWALLET)));
    result.push_back(Pair("bantime-bandwidthabuse", (int64_t)FIREWALL_BANTIME_BANDWIDTHABUSE));
    result.push_back(Pair("bantime-invalidwallet", (int64_t)FIREWALL_BANTIME_INVALIDWALLET));
    result.push_back(Pair("bantime-forkedwallet", (int64_t)FIREWALL_BANTIME_FORKEDWALLET));
    result.push_back(Pair("bantime-floodingwallet", (int64_t)FIREWALL_BANTIME_FLOODINGWALLET));

    return result;
}


UniValue firewallenabled(const JSONRPCRequest& request)
{
    std::string strCommand = "true";
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallenabled \"true|false\"\n"
                            "\nChange the status of Bitcoin Firewall.\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - true\n"
                            + HelpExampleCli("firewallenabled", "true")
                            + HelpExampleCli("firewallenabled", "false")
                            );

    if (request.params.size() == 1)
    {
        strCommand = request.params[0].get_str();
    }

    if (strCommand == "true")
    {
        FIREWALL_ENABLED = true;
    }
    else
    {
        FIREWALL_ENABLED = false;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("enabled", strCommand));

    return result;
}


UniValue firewallclearbanlist(const JSONRPCRequest& request)
{
    std::string strCommand = "true";
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallclearbanlist \"true|false\"\n"
                            "\nBitcoin Firewall Clear Ban List (permenant)\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - false\n"
                            + HelpExampleCli("firewallclearbanlist", "true")
                            + HelpExampleCli("firewallclearbanlist", "false")
                            );

    if (request.params.size() == 1)
    {
        strCommand = request.params[0].get_str();
    }

    if (strCommand == "true")
    {
        FIREWALL_CLEAR_BANS = true;
    }
    else
    {
        FIREWALL_CLEAR_BANS = false;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("clear-banlist", strCommand));

    return result;
}


UniValue firewalldebug(const JSONRPCRequest& request)
{
    std::string strCommand = "true";
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewalldebug \"true|false\"\n"
                            "\nBitcoin Firewall Live Debug Output\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - false\n"
                            + HelpExampleCli("firewalldebug", "true")
                            + HelpExampleCli("firewalldebug", "false")
                            );

    if (request.params.size() == 1)
    {
        strCommand = request.params[0].get_str();
    }

    if (strCommand == "true")
    {
        FIREWALL_LIVE_DEBUG = true;
    }
    else
    {
        FIREWALL_LIVE_DEBUG = false;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("live-debug", strCommand));

    return result;
}

UniValue firewalldebugexam(const JSONRPCRequest& request)
{
    std::string strCommand = "true";
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewalldebugexam \"true|false\"\n"
                            "\nBitcoin Firewall Live Debug Output - Exam\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - true\n"
                            + HelpExampleCli("firewalldebugexam", "true")
                            + HelpExampleCli("firewalldebugexam", "false")
                            );

    if (request.params.size() == 1)
    {
        strCommand = request.params[0].get_str();
    }

    if (strCommand == "true")
    {
        FIREWALL_LIVEDEBUG_EXAM = true;
    }
    else
    {
        FIREWALL_LIVEDEBUG_EXAM = false;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("live-debug-exam", strCommand));

    return result;
}


UniValue firewalldebugbans(const JSONRPCRequest& request)
{
    std::string strCommand = "true";
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewalldebugbans \"true|false\"\n"
                            "\nBitcoin Firewall Live Debug Output - Bans\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - true\n"
                            + HelpExampleCli("firewalldebugbans", "true")
                            + HelpExampleCli("firewalldebugbans", "false")
                            );

    if (request.params.size() == 1)
    {
        strCommand = request.params[0].get_str();
    }

    if (strCommand == "true")
    {
        FIREWALL_LIVEDEBUG_BANS = true;
    }
    else
    {
        FIREWALL_LIVEDEBUG_BANS = false;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("live-debug-bans", strCommand));

    return result;
}


UniValue firewalldebugdisconnect(const JSONRPCRequest& request)
{
    std::string strCommand = "true";
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewalldebugdisconnect \"true|false\"\n"
                            "\nBitcoin Firewall Live Debug Output - Disconnect\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - true\n"
                            + HelpExampleCli("firewalldebugdisconnect", "true")
                            + HelpExampleCli("firewalldebugdisconnect", "false")
                            );

    if (request.params.size() == 1)
    {
        strCommand = request.params[0].get_str();
    }

    if (strCommand == "true")
    {
        FIREWALL_LIVEDEBUG_DISCONNECT = true;
    }
    else
    {
        FIREWALL_LIVEDEBUG_DISCONNECT = false;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("live-debug-disconnect", strCommand));

    return result;
}


UniValue firewalldebugbandwidthabuse(const JSONRPCRequest& request)
{
    std::string strCommand = "true";
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewalldebugbandwidthabuse \"true|false\"\n"
                            "\nBitcoin Firewall Live Debug Output - Bandwidth Abuse\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - true\n"
                            + HelpExampleCli("firewalldebugbandwidthabuse", "true")
                            + HelpExampleCli("firewalldebugbandwidthabuse", "false")
                            );

    if (request.params.size() == 1)
    {
        strCommand = request.params[0].get_str();
    }

    if (strCommand == "true")
    {
        FIREWALL_LIVEDEBUG_BANDWIDTHABUSE = true;
    }
    else
    {
        FIREWALL_LIVEDEBUG_BANDWIDTHABUSE = false;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("live-debug-bandwidthabuse", strCommand));

    return result;
}


UniValue firewalldebugnofalsepositivebandwidthabuse(const JSONRPCRequest& request)
{
    std::string strCommand = "true";
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewalldebugnofalsepositivebandwidthabuse \"true|false\"\n"
                            "\nBitcoin Firewall Live Debug Output - No False Positive (Bandwidth Abuse)\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - true\n"
                            + HelpExampleCli("firewalldebugnofalsepositivebandwidthabuse", "true")
                            + HelpExampleCli("firewalldebugnofalsepositivebandwidthabuse", "false")
                            );

    if (request.params.size() == 1)
    {
        strCommand = request.params[0].get_str();
    }

    if (strCommand == "true")
    {
        FIREWALL_LIVEDEBUG_NOFALSEPOSITIVE = true;
    }
    else
    {
        FIREWALL_LIVEDEBUG_NOFALSEPOSITIVE = false;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("live-debug-nofalsepositive", strCommand));

    return result;
}


UniValue firewalldebuginvalidwallet(const JSONRPCRequest& request)
{
    std::string strCommand = "true";
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewalldebuginvalidwallet \"true|false\"\n"
                            "\nBitcoin Firewall Live Debug Output - Invalid Wallet\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - true\n"
                            + HelpExampleCli("firewalldebuginvalidwallet", "true")
                            + HelpExampleCli("firewalldebuginvalidwallet", "false")
                            );

    if (request.params.size() == 1)
    {
        strCommand = request.params[0].get_str();
    }

    if (strCommand == "true")
    {
        FIREWALL_LIVEDEBUG_INVALIDWALLET = true;
    }
    else
    {
        FIREWALL_LIVEDEBUG_INVALIDWALLET = false;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("live-debug-invalidwallet", strCommand));

    return result;
}


UniValue firewalldebugforkedwallet(const JSONRPCRequest& request)
{
    std::string strCommand = "true";
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewalldebugforkedwallet \"true|false\"\n"
                            "\nBitcoin Firewall Live Debug Output - Forked Wallet\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - true\n"
                            + HelpExampleCli("firewalldebugforkedwallet", "true")
                            + HelpExampleCli("firewalldebugforkedwallet", "false")
                            );

    if (request.params.size() == 1)
    {
        strCommand = request.params[0].get_str();
    }

    if (strCommand == "true")
    {
        FIREWALL_LIVEDEBUG_FORKEDWALLET = true;
    }
    else
    {
        FIREWALL_LIVEDEBUG_FORKEDWALLET = false;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("live-debug-forkedwallet", strCommand));

    return result;
}


UniValue firewalldebugfloodingwallet(const JSONRPCRequest& request)
{
    std::string strCommand = "true";
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewalldebugfloodingwallet \"true|false\"\n"
                            "\nBitcoin Firewall Live Debug Output - Flooding Wallet\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewalldebugfloodingwallet", "true")
                            + HelpExampleCli("firewalldebugfloodingwallet", "false")
                            );

    if (request.params.size() == 1)
    {
        strCommand = request.params[0].get_str();
    }

    if (strCommand == "true")
    {
        FIREWALL_LIVEDEBUG_FLOODINGWALLET = true;
    }
    else
    {
        FIREWALL_LIVEDEBUG_FLOODINGWALLET = false;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("live-debug-floodingwallet", strCommand));

    return result;
}


UniValue firewallaveragetolerance(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallaveragetolerance \"tolerance\"\n"
                            "\nBitcoin Firewall Exam Setting (Average Block Tolerance)\n"
                            "\nArguments:\n"
                            "Value: \"tolerance\" (double, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewallaveragetolerance", "0.0001")
                            + HelpExampleCli("firewallaveragetolerance", "0.1")
                            );

    if (request.params.size() == 1)
    {
        FIREWALL_AVERAGE_TOLERANCE = strtod(request.params[0].get_str().c_str(), NULL);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("exam-average-tolerance", FIREWALL_AVERAGE_TOLERANCE));

    return result;
}


UniValue firewallaveragerange(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallaveragerange \"zone\"\n"
                            "\nBitcoin Firewall Exam Setting (Average Block Range)\n"
                            "\nArguments:\n"
                            "Value: \"zone\" (integer), required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewallaveragerange", "10")
                            + HelpExampleCli("firewallaveragerange", "50")
                            );

    if (request.params.size() == 1)
    {
        FIREWALL_AVERAGE_RANGE = (int)strtod(request.params[0].get_str().c_str(), NULL);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("exam-average-range", FIREWALL_AVERAGE_RANGE));

    return result;
}


UniValue firewalltraffictolerance(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewalltraffictolerance \"tolerance\"\n"
                            "\nBitcoin Firewall Exam Setting (Traffic Tolerance)\n"
                            "\nArguments:\n"
                            "Value: \"tolerance\" (double, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewalltraffictolerance", "0.0001")
                            + HelpExampleCli("firewalltraffictolerance", "0.1")
                            );

    if (request.params.size() == 1)
    {
        FIREWALL_TRAFFIC_TOLERANCE = strtod(request.params[0].get_str().c_str(), NULL);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("exam-traffic-tolerance", FIREWALL_TRAFFIC_TOLERANCE));

    return result;
}


UniValue firewalltrafficzone(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewalltrafficzone \"zone\"\n"
                            "\nBitcoin Firewall Exam Setting (Traffic Zone)\n"
                            "\nArguments:\n"
                            "Value: \"zone\" (double), required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewalltrafficzone", "10.10")
                            + HelpExampleCli("firewalltrafficzone", "50.50")
                            );

    if (request.params.size() == 1)
    {
        FIREWALL_TRAFFIC_ZONE = strtod(request.params[0].get_str().c_str(), NULL);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("exam-traffic-zone", FIREWALL_TRAFFIC_ZONE));

    return result;
}


UniValue firewalldetectbandwidthabuse(const JSONRPCRequest& request)
{
    std::string strCommand = "true";
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewalldetectbandwidthabuse \"true|false\"\n"
                            "\nBitcoin Firewall Detect Bandwidth Abuse Rule #1\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewalldetectbandwidthabuse", "true")
                            + HelpExampleCli("firewalldetectbandwidthabuse", "false")
                            );

    if (request.params.size() == 1)
    {
        strCommand = request.params[0].get_str();
    }

    if (strCommand == "true")
    {
        FIREWALL_DETECT_BANDWIDTHABUSE = true;
    }
    else
    {
        FIREWALL_DETECT_BANDWIDTHABUSE = false;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("detect-bandwidthabuse", strCommand));

    return result;
}


UniValue firewallbanbandwidthabuse(const JSONRPCRequest& request)
{
    std::string strCommand = "true";
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallbanbandwidthabuse \"true|false\"\n"
                            "\nBitcoin Firewall Ban Bandwidth Abuse Rule #1 (permenant)\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewallbanbandwidthabuse", "true")
                            + HelpExampleCli("firewallbanbandwidthabuse", "false")
                            );

    if (request.params.size() == 1)
    {
        strCommand = request.params[0].get_str();
    }

    if (strCommand == "true")
    {
        FIREWALL_BAN_BANDWIDTHABUSE = true;
    }
    else
    {
        FIREWALL_BAN_BANDWIDTHABUSE = false;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("ban-bandwidthabuse", strCommand));

    return result;
}


UniValue firewallnofalsepositivebandwidthabuse(const JSONRPCRequest& request)
{
    std::string strCommand = "true";
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallnofalsepositivebandwidthabuse \"true|false\"\n"
                            "\nBitcoin Firewall False Positive Protection Rule #1\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewallnofalsepositivebandwidthabuse", "true")
                            + HelpExampleCli("firewallnofalsepositivebandwidthabuse", "false")
                            );

    if (request.params.size() == 1)
    {
        strCommand = request.params[0].get_str();
    }

    if (strCommand == "true")
    {
        FIREWALL_NOFALSEPOSITIVE_BANDWIDTHABUSE = true;
    }
    else
    {
        FIREWALL_NOFALSEPOSITIVE_BANDWIDTHABUSE = false;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("firewallnofalsepositivebandwidthabuse", strCommand));

    return result;
}


UniValue firewallbantimebandwidthabuse(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallbantimebandwidthabuse \"seconds\"\n"
                            "\nBitcoin Firewall Ban Time Bandwidth Abuse Rule #1\n"
                            "\nArguments:\n"
                            "Value: \"0|10000\" (integer, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - 24h\n"
                            + HelpExampleCli("firewallbantimebandwidthabuse", "0")
                            + HelpExampleCli("firewallbantimebandwidthabuse", "10000000")
                            );

    if (request.params.size() == 1)
    {
        FIREWALL_BANTIME_BANDWIDTHABUSE = (int)strtod(request.params[0].get_str().c_str(), NULL);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("bantime-bandwidthabuse", FIREWALL_BANTIME_BANDWIDTHABUSE));

    return result;
}


UniValue firewallbandwidthabusemaxcheck(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallbandwidthabusemaxcheck \"seconds\"\n"
                            "\nBitcoin Firewall Max Check Bandwidth Abuse Rule #1\n"
                            "\nArguments:\n"
                            "Seconds: \"0|10000\" (integer, required)\n"
                            "\nExamples:\n"
                            "\n0 = default\n"
                            + HelpExampleCli("firewallbandwidthabusemaxcheck", "0")
                            + HelpExampleCli("firewallbandwidthabusemaxcheck", "10000000")
                            );

    if (request.params.size() == 1)
    {
        FIREWALL_BANDWIDTHABUSE_MAXCHECK = (int)strtod(request.params[0].get_str().c_str(), NULL);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("maxcheck-bandwidthabuse", FIREWALL_BANDWIDTHABUSE_MAXCHECK));

    return result;
}

UniValue firewallbandwidthabuseminattack(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallbandwidthabuseminattack \"value\"\n"
                            "\nBitcoin Firewall Min Attack Bandwidth Abuse Rule #1\n"
                            "\nArguments:\n"
                            "Value: \"17.1\" (double, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - 17.1\n"
                            + HelpExampleCli("firewallbandwidthabuseminattack", "17.1")
                            + HelpExampleCli("firewallbandwidthabuseminattack", "17.005")
                            );

    if (request.params.size() == 1)
    {
        FIREWALL_BANDWIDTHABUSE_MINATTACK = strtod(request.params[0].get_str().c_str(), NULL);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("minattack-bandwidthabuse", FIREWALL_BANDWIDTHABUSE_MINATTACK));

    return result;
}

UniValue firewallbandwidthabusemaxattack(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallbandwidthabusemaxattack \"ratio\"\n"
                            "\nBitcoin Firewall Max Attack Bandwidth Abuse Rule #1\n"
                            "\nArguments:\n"
                            "Value: \"17.2\" (double, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - 17.2\n"
                            + HelpExampleCli("firewallbandwidthabusemaxattack", "17.2")
                            + HelpExampleCli("firewallbandwidthabusemaxattack", "18.004")
                            );

    if (request.params.size() == 1)
    {
        FIREWALL_BANDWIDTHABUSE_MAXATTACK = strtod(request.params[0].get_str().c_str(), NULL);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("maxattack-bandwidthabuse", FIREWALL_BANDWIDTHABUSE_MAXATTACK));

    return result;
}


UniValue firewalldetectinvalidwallet(const JSONRPCRequest& request)
{
    std::string strCommand = "true";
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewalldetectinvalidwallet \"true|false\"\n"
                            "\nBitcoin Firewall Detect Invalid Wallet Rule #2\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewalldetectinvalidwallet", "true")
                            + HelpExampleCli("firewalldetectinvalidwallet", "false")
                            );

    if (request.params.size() == 1)
    {
        strCommand = request.params[0].get_str();
    }

    if (strCommand == "true")
    {
        FIREWALL_DETECT_INVALIDWALLET  = true;
    }
    else
    {
        FIREWALL_DETECT_INVALIDWALLET  = false;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("detect-invalidwallet", strCommand));

    return result;
}


UniValue firewallbaninvalidwallet(const JSONRPCRequest& request)
{
    std::string strCommand = "true";
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallbaninvalidwallet \"true|false\"\n"
                            "\nBitcoin Firewall Ban Invalid Wallet Rule #2 (permenant)\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewallbaninvalidwallet", "true")
                            + HelpExampleCli("firewallbaninvalidwallet", "false")
                            );

    if (request.params.size() == 1)
    {
        strCommand = request.params[0].get_str();
    }

    if (strCommand == "true")
    {
        FIREWALL_BAN_INVALIDWALLET = true;
    }
    else
    {
        FIREWALL_BAN_INVALIDWALLET = false;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("ban-invalidwallet", strCommand));

    return result;
}


UniValue firewallbantimeinvalidwallet(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallbantimeinvalidwallet \"seconds\"\n"
                            "\nBitcoin Firewall Ban Time Invalid Wallet Rule #2\n"
                            "\nArguments:\n"
                            "Value: \"0|100000\" (integer, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - 24h\n"
                            + HelpExampleCli("firewallbantimeinvalidwallet", "0")
                            + HelpExampleCli("firewallbantimeinvalidwallet", "10000000")
                            );

    if (request.params.size() == 1)
    {
        FIREWALL_BANTIME_INVALIDWALLET = (int)strtod(request.params[0].get_str().c_str(), NULL);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("bantime-invalidwallet", FIREWALL_BANTIME_INVALIDWALLET));

    return result;
}


UniValue firewallinvalidwalletminprotocol(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallinvalidwalletminprotocol \"protocol\"\n"
                            "\nBitcoin Firewall Min Protocol Invalid Wallet Rule #2\n"
                            "\nArguments:\n"
                            "Value: \"0|100000\" (integer, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - \n"
                            + HelpExampleCli("firewallinvalidwalletminprotocol", "0")
                            + HelpExampleCli("firewallinvalidwalletminprotocol", "10000000")
                            );

    if (request.params.size() == 1)
    {
        FIREWALL_MINIMUM_PROTOCOL = (int)strtod(request.params[0].get_str().c_str(), NULL);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("minprotocol-invalidwallet", FIREWALL_MINIMUM_PROTOCOL));

    return result;
}


UniValue firewallinvalidwalletmaxcheck(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallinvalidwalletmaxcheck \"seconds\"\n"
                            "\nBitcoin Firewall Max Check Invalid Wallet Rule #2\n"
                            "\nArguments:\n"
                            "Value: \"0|100000\" (integer, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - \n"
                            + HelpExampleCli("firewallinvalidwalletmaxcheck", "0")
                            + HelpExampleCli("firewallinvalidwalletmaxcheck", "10000000")
                            );

    if (request.params.size() == 1)
    {
        FIREWALL_INVALIDWALLET_MAXCHECK = (int)strtod(request.params[0].get_str().c_str(), NULL);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("maxcheck-invalidwallet", FIREWALL_INVALIDWALLET_MAXCHECK));

    return result;
}


UniValue firewalldetectforkedwallet(const JSONRPCRequest& request)
{
    std::string strCommand = "true";
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewalldetectforkedwallet \"true|false\"\n"
                            "\nBitcoin Firewall Detect Forked Wallet Rule #3\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewalldetectforkedwallet", "true")
                            + HelpExampleCli("firewalldetectforkedwallet", "false")
                            );

    if (request.params.size() == 1)
    {
        strCommand = request.params[0].get_str();
    }

    if (strCommand == "true")
    {
        FIREWALL_DETECT_FORKEDWALLET = true;
    }
    else
    {
        FIREWALL_DETECT_FORKEDWALLET = false;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("detect-forkedwallet", strCommand));

    return result;
}


UniValue firewallbanforkedwallet(const JSONRPCRequest& request)
{
    std::string strCommand = "true";
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallbanforkedwallet \"true|false\"\n"
                            "\nBitcoin Firewall Ban Forked Wallet Rule #3 (permenant)\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewallbanforkedwallet", "true")
                            + HelpExampleCli("firewallbanforkedwallet", "false")
                            );

    if (request.params.size() == 1)
    {
        strCommand = request.params[0].get_str();
    }

    if (strCommand == "true")
    {
        FIREWALL_BAN_FORKEDWALLET = true;
    }
    else
    {
        FIREWALL_BAN_FORKEDWALLET = false;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("ban-forkedwallet", strCommand));

    return result;
}


UniValue firewallbantimeforkedwallet(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallbantimeforkedwallet \"seconds\"\n"
                            "\nBitcoin Firewall Ban Time Forked Wallet Rule #3\n"
                            "\nArguments:\n"
                            "Value: \"seconds\" (integer, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - 24h\n"
                            + HelpExampleCli("firewallbantimeinvalidwallet", "0")
                            + HelpExampleCli("firewallbantimeinvalidwallet", "10000000")
                            );

    if (request.params.size() == 1)
    {
         FIREWALL_BANTIME_FORKEDWALLET = (int)strtod(request.params[0].get_str().c_str(), NULL);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("bantime-forkedwallet", FIREWALL_BANTIME_FORKEDWALLET));

    return result;
}


UniValue firewallforkedwalletnodeheight(const JSONRPCRequest& request)
{
    std::string MSG;

    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallforkedwalletnodeheight \"blockheight\"\n"
                            "\nBitcoin Firewall Adds Forked NodeHeight Flooding Wallet Rule #3\n"
                            "\nArguments:\n"
                            "Value: \"blockheight\" (int, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - \n"
                            + HelpExampleCli("firewallforkedwalletnodeheight", "0")
                            + HelpExampleCli("firewallforkedwalletnodeheight", "10000000")
                            );

    if (request.params.size() == 1)
    {
        if (CountIntArray(FIREWALL_FORKED_NODEHEIGHT) < 256)
        {
            FIREWALL_FORKED_NODEHEIGHT[CountIntArray(FIREWALL_FORKED_NODEHEIGHT)] = (int)strtod(request.params[0].get_str().c_str(), NULL);
            MSG = CountIntArray(FIREWALL_FORKED_NODEHEIGHT);
        }
        else
        {
            MSG = "Over 256 Max!";
        }
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("attackpattern-forkedwallet-nodeheight-add", MSG));

    return result;
}


UniValue firewalldetectfloodingwallet(const JSONRPCRequest& request)
{
    std::string strCommand = "true";
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewalldetectfloodingwallet \"true|false\"\n"
                            "\nBitcoin Firewall Detect Flooding Wallet Rule #4\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewalldetectfloodingwallet", "true")
                            + HelpExampleCli("firewalldetectfloodingwallet", "false")
                            );

    if (request.params.size() == 1)
    {
        strCommand = request.params[0].get_str();
    }

    if (strCommand == "true")
    {
        FIREWALL_DETECT_FLOODINGWALLET = true;
    }
    else
    {
        FIREWALL_DETECT_FLOODINGWALLET = false;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("detect-floodingwallet", strCommand));

    return result;
}


UniValue firewallbanfloodingwallet(const JSONRPCRequest& request)
{
    std::string strCommand = "true";
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallbanfloodingwallet \"true|false\"\n"
                            "\nBitcoin Firewall Ban Flooding Wallet Rule #4 (permenant)\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewallbanfloodingwallet", "true")
                            + HelpExampleCli("firewallbanfloodingwallet", "false")
                            );

    if (request.params.size() == 1)
    {
        strCommand = request.params[0].get_str();
    }

    if (strCommand == "true")
    {
        FIREWALL_BAN_FLOODINGWALLET = true;
    }
    else
    {
        FIREWALL_BAN_FLOODINGWALLET = false;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("ban-floodingwallet", strCommand));

    return result;
}


UniValue firewallbantimefloodingwallet(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallbantimefloodingwallet \"seconds\"\n"
                            "\nBitcoin Firewall Ban Time Flooding Wallet Rule #4\n"
                            "\nArguments:\n"
                            "Value: \"seconds\" (integer, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - 24h\n"
                            + HelpExampleCli("firewallbantimefloodingwallet", "0")
                            + HelpExampleCli("firewallbantimefloodingwallet", "10000000")
                            );

    if (request.params.size() == 1)
    {
        FIREWALL_BANTIME_FLOODINGWALLET = (int)strtod(request.params[0].get_str().c_str(), NULL);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("bantime-floodingwallet", FIREWALL_BANTIME_FLOODINGWALLET));

    return result;
}


UniValue firewallfloodingwalletminbytes(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallfloodingwalletminbytes \"bytes\"\n"
                            "\nBitcoin Firewall Min Bytes Flooding Wallet Rule #4\n"
                            "\nArguments:\n"
                            "Value: \"Bytes\" (integer, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - h\n"
                            + HelpExampleCli("firewallfloodingwalletminbytes", "0")
                            + HelpExampleCli("firewallfloodingwalletminbytes", "10000000")
                            );

    if (request.params.size() == 1)
    {
        FIREWALL_FLOODINGWALLET_MINBYTES = (int)strtod(request.params[0].get_str().c_str(), NULL);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("minbytes-floodingwallet", FIREWALL_FLOODINGWALLET_MINBYTES));

    return result;
}


UniValue firewallfloodingwalletmaxbytes(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallfloodingwalletmaxbytes \"bytes\"\n"
                            "\nBitcoin Firewall Max Bytes Flooding Wallet Rule #4\n"
                            "\nArguments:\n"
                            "Value: \"bytes\" (integer, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - \n"
                            + HelpExampleCli("firewallfloodingwalletmaxbytes", "0")
                            + HelpExampleCli("firewallfloodingwalletmaxbytes", "10000000")
                            );

    if (request.params.size() == 1)
    {
        FIREWALL_FLOODINGWALLET_MAXBYTES = (int)strtod(request.params[0].get_str().c_str(), NULL);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("bantime-floodingwallet", FIREWALL_FLOODINGWALLET_MAXBYTES));

    return result;
}


UniValue firewallfloodingwalletattackpatternadd(const JSONRPCRequest& request)
{
    std::string MSG;

    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallfloodingwalletattackpatternadd \"warnings\"\n"
                            "\nBitcoin Firewall Adds Attack Pattern Flooding Wallet Rule #4\n"
                            "\nArguments:\n"
                            "Value: \"warnings\" (string, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - \n"
                            + HelpExampleCli("firewallfloodingwalletattackpatternadd", "0")
                            + HelpExampleCli("firewallfloodingwalletattackpatternadd", "10000000")
                            );

    if (request.params.size() == 1)
    {
        if (CountStringArray(FIREWALL_FLOODPATTERNS) < 256)
        {
            FIREWALL_FLOODPATTERNS[CountStringArray(FIREWALL_FLOODPATTERNS)] = request.params[0].get_str().c_str();
            MSG = CountStringArray(FIREWALL_FLOODPATTERNS);
        }
        else
        {
            MSG = "Over 256 Max!";
        }
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("attackpattern-floodingwallet-attackpattern-add", MSG));

    return result;
}


UniValue firewallfloodingwalletattackpatternremove(const JSONRPCRequest& request)
{
    std::string MSG;
    int i;

    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallfloodingwalletattackpatternremove \"warnings\"\n"
                            "\nBitcoin Firewall Remove Attack Pattern Flooding Wallet Rule #4\n"
                            "\nArguments:\n"
                            "Value: \"warnings\" (string, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - \n"
                            + HelpExampleCli("firewallfloodingwalletattackpatternremove", "0")
                            + HelpExampleCli("firewallfloodingwalletattackpatternremove", "10000000")
                            );

    if (request.params.size() == 1)
    {
        std::string WARNING;
        int TmpFloodPatternsCount;
        WARNING = request.params[0].get_str().c_str();
        TmpFloodPatternsCount = CountStringArray(FIREWALL_FLOODPATTERNS);

        MSG = "Not Found";

        for (i = 0; i < TmpFloodPatternsCount; i++)
        {  
            if (WARNING == FIREWALL_FLOODPATTERNS[i])
            {
                MSG = FIREWALL_FLOODPATTERNS[i];
                FIREWALL_FLOODPATTERNS[i] = "";
            }

        }
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("attackpattern-floodingwallet-attackpattern-remove", MSG));

    return result;
}


UniValue firewallfloodingwalletmintrafficavg(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallfloodingwalletmintrafficavg \"ratio\"\n"
                            "\nBitcoin Firewall Min Traffic Average Flooding Wallet Rule #4\n"
                            "\nArguments:\n"
                            "Value: \"ratio\" (double, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - 2000\n"
                            + HelpExampleCli("firewallfloodingwalletmintrafficav", "20000.01")
                            + HelpExampleCli("firewallfloodingwalletmintrafficav", "12000.014")
                            );

    if (request.params.size() == 1)
    {
        FIREWALL_FLOODINGWALLET_MINTRAFFICAVERAGE = strtod(request.params[0].get_str().c_str(), NULL);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("mintrafficavg-floodingwallet", FIREWALL_FLOODINGWALLET_MINTRAFFICAVERAGE));

    return result;
}


UniValue firewallfloodingwalletmaxtrafficavg(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallbantimefloodingwallet \"ratio\"\n"
                            "\nBitcoin Firewall Max Traffic Average Flooding Wallet Rule #4\n"
                            "\nArguments:\n"
                            "Value: \"ratio\" (double, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - \n"
                            + HelpExampleCli("firewallfloodingwalletmaxtrafficavg", "100.10")
                            + HelpExampleCli("ffirewallfloodingwalletmaxtrafficavg", "10.8")
                            );

    if (request.params.size() == 1)
    {
        FIREWALL_FLOODINGWALLET_MAXTRAFFICAVERAGE = strtod(request.params[0].get_str().c_str(), NULL);;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("trafficavg-floodingwallet", FIREWALL_FLOODINGWALLET_MAXTRAFFICAVERAGE));

    return result;
}


UniValue firewallfloodingwalletmincheck(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallfloodingwalletmincheck \"seconds\"\n"
                            "\nBitcoin Firewall Ban Time Flooding Wallet Rule #4\n"
                            "\nArguments:\n"
                            "Value: \"seconds\" (integer, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - \n"
                            + HelpExampleCli("firewallfloodingwalletmincheck", "0")
                            + HelpExampleCli("firewallfloodingwalletmincheck", "10000000")
                            );

    if (request.params.size() == 1)
    {
        FIREWALL_FLOODINGWALLET_MINCHECK = (int)strtod(request.params[0].get_str().c_str(), NULL);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("mincheck-floodingwallet", FIREWALL_FLOODINGWALLET_MINCHECK));

    return result;
}


UniValue firewallfloodingwalletmaxcheck(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                            "firewallfloodingwalletmaxcheck \"seconds\"\n"
                            "\nBitcoin Firewall Max Check Flooding Wallet Rule #4\n"
                            "\nArguments:\n"
                            "Value: \"seconds\" (integer, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - \n"
                            + HelpExampleCli("firewallfloodingwalletmaxcheck", "0")
                            + HelpExampleCli("firewallfloodingwalletmaxcheck", "10000000")
                            );

    if (request.params.size() == 1)
    {
        FIREWALL_FLOODINGWALLET_MAXCHECK = (int)strtod(request.params[0].get_str().c_str(), NULL);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("maxcheck-floodingwallet", FIREWALL_FLOODINGWALLET_MAXCHECK));

    return result;
}

static const CRPCCommand commands[] =
{ //  category              name                                                  actor (function)                                     argNames
  //  --------------------- ----------------------------------------------------- ---------------------------------------------------  ----------
    { "network",            "getconnectioncount",                                 &getconnectioncount,                                 {} },
    { "network",            "ping",                                               &ping,                                               {} },
    { "network",            "getpeerinfo",                                        &getpeerinfo,                                        {} },
    { "network",            "addnode",                                            &addnode,                                            {"node","command"} },
    { "network",            "disconnectnode",                                     &disconnectnode,                                     {"address", "nodeid"} },
    { "network",            "getaddednodeinfo",                                   &getaddednodeinfo,                                   {"node"} },
    { "network",            "getnettotals",                                       &getnettotals,                                       {} },
    { "network",            "getnetworkinfo",                                     &getnetworkinfo,                                     {} },
    { "network",            "setban",                                             &setban,                                             {"subnet", "command", "bantime", "absolute"} },
    { "network",            "listbanned",                                         &listbanned,                                         {} },
    { "network",            "clearbanned",                                        &clearbanned,                                        {} },
    { "network",            "setnetworkactive",                                   &setnetworkactive,                                   {"state"} },
    { "network",            "firewallstatus",                                     &firewallstatus,                                     {} },
    { "network",            "firewallenabled",                                    &firewallenabled,                                    {"state"} },
    { "network",            "firewallclearbanlist",                               &firewallclearbanlist,                               {"state"} }, 
    { "network",            "firewalldebug",                                      &firewalldebug,                                      {"state"} },
    { "network",            "firewalldebugexam",                                  &firewalldebugexam,                                  {"state"} },
    { "network",            "firewalldebugbans",                                  &firewalldebugbans,                                  {"state"} },
    { "network",            "firewalldebugdisconnect",                            &firewalldebugdisconnect,                            {"state"} },
    { "network",            "firewalldebugbandwidthabuse",                        &firewalldebugbandwidthabuse,                        {"state"} },
    { "network",            "firewalldebugnofalsepositivebandwidthabuse",         &firewalldebugnofalsepositivebandwidthabuse,         {"state"} },
    { "network",            "firewalldebuginvalidwallet",                         &firewalldebuginvalidwallet,                         {"state"} },
    { "network",            "firewalldebugfloodingwallet",                        &firewalldebugfloodingwallet,                        {"state"} },
    { "network",            "firewallaveragetolerance",                           &firewallaveragetolerance,                           {"tolerance"} },
    { "network",            "firewallaveragerange",                               &firewallaveragerange,                               {"state"} },
    { "network",            "firewalltraffictolerance",                           &firewalltraffictolerance,                           {"tolerance"} },
    { "network",            "firewalltrafficzone",                                &firewalltrafficzone,                                {"zone"} },
    { "network",            "firewalldetectbandwidthabuse",                       &firewalldetectbandwidthabuse,                       {"state"} },
    { "network",            "firewallnofalsepositivebandwidthabuse",              &firewallnofalsepositivebandwidthabuse,              {"state""state"} },
    { "network",            "firewallbantimebandwidthabuse",                      &firewallbantimebandwidthabuse,                      {"seconds"} },
    { "network",            "firewallbandwidthabusemaxcheck",                     &firewallbandwidthabusemaxcheck,                     {"seconds"} },
    { "network",            "firewallbandwidthabuseminattack",                    &firewallbandwidthabuseminattack,                    {"ratio"} },
    { "network",            "firewallbandwidthabusemaxattack",                    &firewallbandwidthabusemaxattack,                    {"ratio"} },
    { "network",            "firewalldetectinvalidwallet",                        &firewalldetectinvalidwallet,                        {"state"} },
    { "network",            "firewallbaninvalidwallet",                           &firewallbaninvalidwallet,                           {"state"} },
    { "network",            "firewallbantimeinvalidwallet",                       &firewallbantimeinvalidwallet,                       {"seconds"} },
    { "network",            "firewallinvalidwalletminprotocol",                   &firewallinvalidwalletminprotocol,                   {"state"} },
    { "network",            "firewallinvalidwalletmaxcheck",                      &firewallinvalidwalletmaxcheck,                      {"state"} },
    { "network",            "firewallforkedwalletnodeheight",                     &firewallforkedwalletnodeheight,                     {"height"} },
    { "network",            "firewalldetectforkedwallet",                         &firewalldetectforkedwallet,                         {"state"} },
    { "network",            "firewallbanforkedwallet",                            &firewallbanforkedwallet,                            {"state"} },
    { "network",            "firewallbantimeforkedwallet",                        &firewallbantimeforkedwallet,                        {"seconds"} },
    { "network",            "firewalldetectfloodingwallet",                       &firewalldetectfloodingwallet,                       {"state"} },
    { "network",            "firewallbanfloodingwallet",                          &firewallbanfloodingwallet,                          {"state"} },
    { "network",            "firewallbantimefloodingwallet",                      &firewallbantimefloodingwallet,                      {"seconds"} },
    { "network",            "firewallfloodingwalletminbytes",                     &firewallfloodingwalletminbytes,                     {"bytes"} },
    { "network",            "firewallfloodingwalletmaxbytes",                     &firewallfloodingwalletmaxbytes,                     {"bytes"} },
    { "network",            "firewallfloodingwalletattackpatternadd",             &firewallfloodingwalletattackpatternadd,             {"warnings"} },
    { "network",            "firewallfloodingwalletattackpatternremove",          &firewallfloodingwalletattackpatternremove,          {"warnings"} },
    { "network",            "firewallfloodingwalletmintrafficavg",                &firewallfloodingwalletmintrafficavg,                {"ratio"} },
    { "network",            "firewallfloodingwalletmaxtrafficavg",                &firewallfloodingwalletmaxtrafficavg,                {"ratio"} },
    { "network",            "firewallfloodingwalletmincheck",                     &firewallfloodingwalletmincheck,                     {"seconds"} },
    { "network",            "firewallfloodingwalletmaxcheck",                     &firewallfloodingwalletmaxcheck,                     {"seconds"} },

};

void RegisterNetRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
