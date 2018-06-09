bool CBlock::AcceptBlock()
{
    AssertLockHeld(cs_main);

    // Remove for BIP-0034 FORK
    if (nVersion > CURRENT_VERSION)
        return DoS(100, error("AcceptBlock() : reject unknown block version %d", nVersion));

    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return error("AcceptBlock() : block already in mapBlockIndex");

    // Get prev block index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashPrevBlock);
    if (mi == mapBlockIndex.end())
        return DoS(10, error("AcceptBlock() : prev block not found"));
    CBlockIndex* pindexPrev = (*mi).second;
    int nHeight = pindexPrev->nHeight+1;

    uint256 hashProof;
    if (IsProofOfWork() && nHeight > Params().LastPOWBlock()){
        return DoS(100, error("AcceptBlock() : reject proof-of-work at height %d", nHeight));
    } else {
        // PoW is checked in CheckBlock()
        if (IsProofOfWork())
        {
            hashProof = GetPoWHash();
        }
    }

    if (IsProofOfStake() && nHeight < Params().POSStartBlock())
        return DoS(100, error("AcceptBlock() : reject proof-of-stake at height <= %d", nHeight));

    // Check coinbase timestamp
    if (GetBlockTime() > FutureDrift((int64_t)vtx[0].nTime) && IsProofOfStake())
        return DoS(50, error("AcceptBlock() : coinbase timestamp is too early"));

    // Check coinstake timestamp
    if (IsProofOfStake() && !CheckCoinStakeTimestamp(nHeight, GetBlockTime(), (int64_t)vtx[1].nTime))
        return DoS(50, error("AcceptBlock() : coinstake timestamp violation nTimeBlock=%d nTimeTx=%u", GetBlockTime(), vtx[1].nTime));

    // Check proof-of-work or proof-of-stake
    if (nBits != GetNextTargetRequired(pindexPrev, IsProofOfStake()) && hash != uint256("0x474619e0a58ec88c8e2516f8232064881750e87acac3a416d65b99bd61246968") && hash != uint256("0x4f3dd45d3de3737d60da46cff2d36df0002b97c505cdac6756d2d88561840b63") && hash != uint256("0x274996cec47b3f3e6cd48c8f0b39c32310dd7ddc8328ae37762be956b9031024"))
        return DoS(100, error("AcceptBlock() : incorrect %s", IsProofOfWork() ? "proof-of-work" : "proof-of-stake"));

    // Check timestamp against prev
    if (GetBlockTime() <= pindexPrev->GetPastTimeLimit() || FutureDrift(GetBlockTime()) < pindexPrev->GetBlockTime())
        return error("AcceptBlock() : block's timestamp is too early");

    // Check that all transactions are finalized
    BOOST_FOREACH(const CTransaction& tx, vtx)
        if (!IsFinalTx(tx, nHeight, GetBlockTime()))
            return DoS(10, error("AcceptBlock() : contains a non-final transaction"));

    // Check that the block chain matches the known block chain up to a checkpoint
    if (!Checkpoints::CheckHardened(nHeight, hash))
        return DoS(100, error("AcceptBlock() : rejected by hardened checkpoint lock-in at %d", nHeight));

    // Verify hash target and signature of coinstake tx
    if (IsProofOfStake())
    {
        uint256 targetProofOfStake;
        if (!CheckProofOfStake(pindexPrev, vtx[1], nBits, hashProof, targetProofOfStake))
        {
            return error("AcceptBlock() : check proof-of-stake failed for block %s", hash.ToString());
        }
    }

    // Check that the block satisfies synchronized checkpoint
    if (!Checkpoints::CheckSync(nHeight))
        return error("AcceptBlock() : rejected by synchronized checkpoint");

    // Enforce rule that the coinbase starts with serialized block height
    CScript expect = CScript() << nHeight;
    if (vtx[0].vin[0].scriptSig.size() < expect.size() ||
        !std::equal(expect.begin(), expect.end(), vtx[0].vin[0].scriptSig.begin()))
        return DoS(100, error("AcceptBlock() : block height mismatch in coinbase"));

    // Write block to history file
    if (!CheckDiskSpace(::GetSerializeSize(*this, SER_DISK, CLIENT_VERSION)))
        return error("AcceptBlock() : out of disk space");
    unsigned int nFile = -1;
    unsigned int nBlockPos = 0;
    if (!WriteToDisk(nFile, nBlockPos))
        return error("AcceptBlock() : WriteToDisk failed");
    if (!AddToBlockIndex(nFile, nBlockPos, hashProof))
        return error("AcceptBlock() : AddToBlockIndex failed");

    // Relay inventory, but don't relay old inventory during initial block download
    int nBlockEstimate = Checkpoints::GetTotalBlocksEstimate();
    if (hashBestChain == hash)
    {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
        {
            // Push Inventory to CNode
            if (nBestHeight > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : nBlockEstimate))
            {
                pnode->PushInventory(CInv(MSG_BLOCK, hash));
            }

            // Push Inventory Height to CNode Data Cache
            if (nHeight > 0)
            {
                pnode->nSyncHeight = nHeight;
            }
        }
    }

    return true;
}








