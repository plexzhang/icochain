// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_MAIN_H
#define BITCOIN_MAIN_H

#include "core.h"
#include "bignum.h"
#include "sync.h"
#include "txmempool.h"
#include "net.h"
#include "script.h"
#include "scrypt.h"
#include "hashblock.h"

#include <limits>
#include <list>

class CBlock;
class CBlockIndex;
class CInv;
class CKeyItem;
class CNode;
class CReserveKey;
class CWallet;

/** The maximum allowed size for a serialized block, in bytes (network rule) */
/** icochain: 2M 根据最终的区块时间设定 */
static const unsigned int MAX_BLOCK_SIZE = 2000000;
/** The maximum size for mined blocks */
static const unsigned int MAX_BLOCK_SIZE_GEN = MAX_BLOCK_SIZE/2;
/** The maximum size for transactions we're willing to relay/mine **/
static const unsigned int MAX_STANDARD_TX_SIZE = MAX_BLOCK_SIZE_GEN/5;
/** The maximum size for data */
/** icochain: 一笔交易最多携带信息量(加密后的字符数，Base64加密，3个英文字母=1个汉字=长度4)*/
static const unsigned int MAX_TX_PAYLOAD_LENGTH = 500;
/** icochain: 交易携带信息每个字符的费用 */
static const int64_t TX_PAYLOAD_PEERCHAR_COST = 0.25 * COIN;
/** icochain: 注册资产最低费用 */
static const int64_t MIN_REGISTER_ASSET_COST = 1000 * COIN;
/** icochain: 注册别名最低费用 */
static const int64_t MIN_REGISTER_ALIAS_COST = 10 * COIN;
/** icochain: 矿工每次从激励池拿总量的 1/10080 */
static const int REWARD_PERIOD_BLOCKS = 10080;
/** icochain: 激励池余额超过这个值才会分配给矿工 */
static const int64_t MIN_INCENTIVE_POOL_BALANCE = 1 * COIN;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const unsigned int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE/50;
/** Maxiumum number of signature check operations in an IsStandard() P2SH script */
static const unsigned int MAX_P2SH_SIGOPS = 15;
/** The maximum number of sigops we're willing to relay/mine in a single tx */
static const unsigned int MAX_TX_SIGOPS = MAX_BLOCK_SIGOPS/5;
/** The maximum number of orphan transactions kept in memory */
static const unsigned int MAX_ORPHAN_TRANSACTIONS = MAX_BLOCK_SIZE/100;
/** Default for -maxorphanblocksmib, maximum number of memory to keep orphan blocks */
static const unsigned int DEFAULT_MAX_ORPHAN_BLOCKS = 40;
/** The maximum number of entries in an 'inv' protocol message */
static const unsigned int MAX_INV_SZ = 50000;
/** icochain: 0.0001 COIN 每Kbyte的最小手续费，同时也是一笔交易的最低手续费 */
static const int64_t MIN_TX_PEERK_FEE = 10000;
/** Fees smaller than this (in satoshi) are considered zero fee (for relaying) */
static const int64_t MIN_RELAY_TX_FEE = MIN_TX_PEERK_FEE;
/** No amount larger than this (in satoshi) is valid */
static const int64_t MAX_MONEY = std::numeric_limits<int64_t>::max();
/** 用户发行资产的最大供应量，防止溢出，64位整数范围：-9223372036854775808 ~ 9223372036854775807(92233720368.54775807*COIN) */
static const int64_t MAX_ASSET_SUPPLY = std::numeric_limits<int64_t>::max();
inline bool MoneyRange(int64_t nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }
/** Threshold for nLockTime: below this value it is interpreted as block number, otherwise as UNIX timestamp. */
static const unsigned int LOCKTIME_THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC
/** icochain: 小企股最大供应量 */
static const int64_t MAX_MONEY_ICS = 13888379 * COIN;
/** icochain: 解决产出bug，修改难度调整参数 */
static const int64_t HARDFORK1_HEIGHT = 20700;
/** icochain: 这个数值表示秒,超过本机机器时间5分钟以内的区块或交易都可以接受 */
inline int64_t FutureDrift(int64_t nTime) { return nTime + 5 * 60; }
/** icochain: 区块间隔时间 */
inline unsigned int GetTargetSpacing(int nHeight)  { return 120; }

extern CScript COINBASE_FLAGS;
extern CCriticalSection cs_main;
extern CTxMemPool mempool;
extern std::map<uint256, CBlockIndex*> mapBlockIndex;
extern std::set<std::pair<COutPoint, unsigned int> > setStakeSeen;
extern CBlockIndex* pindexGenesisBlock;
extern int nStakeMinConfirmations;
extern unsigned int nStakeMinAge;
extern unsigned int nNodeLifespan;
extern int nCoinbaseMaturity;
extern int nBestHeight;
extern uint256 nBestChainTrust;
extern uint256 nBestInvalidTrust;
extern uint256 hashBestChain;
extern CBlockIndex* pindexBest;
extern uint64_t nLastBlockTx;
extern uint64_t nLastBlockSize;
extern int64_t nLastCoinStakeSearchInterval;
extern const std::string strMessageMagic;
extern int64_t nTimeBestReceived;
extern bool fImporting;
extern bool fReindex;
struct COrphanBlock;
extern std::map<uint256, COrphanBlock*> mapOrphanBlocks;
extern bool fHaveGUI;

extern double dHashesPerSec;
extern int64 nHPSTimerStart;

// Settings
extern bool fUseFastIndex;
extern unsigned int nDerivationMethodIndex;

// Minimum disk space required - used in CheckDiskSpace()
static const uint64_t nMinDiskSpace = 52428800;

class CReserveKey;
class CTxDB;
class CTxIndex;
class CWalletInterface;

/** Register a wallet to receive updates from core */
void RegisterWallet(CWalletInterface* pwalletIn);
/** Unregister a wallet from core */
void UnregisterWallet(CWalletInterface* pwalletIn);
/** Unregister all wallets from core */
void UnregisterAllWallets();
/** Push an updated transaction to all registered wallets */
void SyncWithWallets(const CTransaction& tx, const CBlock* pblock = NULL, bool fConnect = true);
/** Ask wallets to resend their transactions */
void ResendWalletTransactions(bool fForce = false);
/** Register with a network node to receive its signals */
void RegisterNodeSignals(CNodeSignals& nodeSignals);
/** Unregister a network node */
void UnregisterNodeSignals(CNodeSignals& nodeSignals);
void PushGetBlocks(CNode* pnode, CBlockIndex* pindexBegin, uint256 hashEnd);

bool ProcessBlock(CNode* pfrom, CBlock* pblock);
bool CheckDiskSpace(uint64_t nAdditionalBytes=0);
FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode="rb");
FILE* AppendBlockFile(unsigned int& nFileRet);
bool LoadBlockIndex(bool fAllowNew=true);
void PrintBlockTree();
CBlockIndex* FindBlockByHeight(int nHeight);
bool ProcessMessages(CNode* pfrom);
bool SendMessages(CNode* pto, bool fSendTrickle);
void ThreadImport(std::vector<boost::filesystem::path> vImportFiles);

bool CheckProofOfWork(uint256 hash, unsigned int nBits);
unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake);
int64_t GetProofOfWorkReward(int nHeight, int64_t nIncPoolBalance, int64_t nFees);
int64_t GetProofOfStakeReward(int64_t nIncPoolBalance, int64_t nFees);

int64_t GetPowNewIssue(int nPowHeight);
int64_t GetPosNewIssue(int nPosHeight);

bool IsInitialBlockDownload();
bool IsConfirmedInNPrevBlocks(const CTxIndex& txindex, const CBlockIndex* pindexFrom, int nMaxDepth, int& nActualDepth);
std::string GetWarnings(std::string strFor);
bool GetTransaction(const uint256 &hash, CTransaction &tx, uint256 &hashBlock);
uint256 WantedByOrphan(const COrphanBlock* pblockOrphan);
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake);
void ThreadStakeMiner(CWallet *pwallet);
void ThreadWorkMiner(CWallet *pwallet);
bool IsExistsAlias(std::string alias);
bool IsExsistAssetMsg(int64_t nAssetIdIn, std::string engNameIn, std::string secondNameIn, std::string symbolIn);
bool GetAssetInformation(int64_t nAssetId, std::string &engName, std::string &secondName, std::string &symbol, std::string &intro, std::string &publisher, int64_t &supply, int &suffix);
bool IsLegalPayload(const std::string& payload);
bool IsLegalAssetPayload(const std::string& engName, const std::string& secondName, const std::string& symbol, const std::string& assetIntro);
bool IsLegalAliasPayload(const std::string& alias);
bool GetMiningStatus();
bool GetStakingStatus();

/** (try to) add transaction to memory pool **/
bool AcceptToMemoryPool(CTxMemPool& pool, CTransaction &tx, bool fLimitFree,
                        bool* pfMissingInputs);

/** Position on disk for a particular transaction. */
class CDiskTxPos
{
public:
    unsigned int nFile;
    unsigned int nBlockPos;
    unsigned int nTxPos;

    CDiskTxPos()
    {
        SetNull();
    }

    CDiskTxPos(unsigned int nFileIn, unsigned int nBlockPosIn, unsigned int nTxPosIn)
    {
        nFile = nFileIn;
        nBlockPos = nBlockPosIn;
        nTxPos = nTxPosIn;
    }

    IMPLEMENT_SERIALIZE( READWRITE(FLATDATA(*this)); )
    void SetNull() { nFile = (unsigned int) -1; nBlockPos = 0; nTxPos = 0; }
    bool IsNull() const { return (nFile == (unsigned int) -1); }

    friend bool operator==(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return (a.nFile     == b.nFile &&
                a.nBlockPos == b.nBlockPos &&
                a.nTxPos    == b.nTxPos);
    }

    friend bool operator!=(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return !(a == b);
    }


    std::string ToString() const
    {
        if (IsNull())
            return "null";
        else
            return strprintf("(nFile=%u, nBlockPos=%u, nTxPos=%u)", nFile, nBlockPos, nTxPos);
    }
};

typedef std::map<uint256, std::pair<CTxIndex, CTransaction> > MapPrevTx;

int64_t GetMinTxChange(const CTransaction& tx, unsigned int nBytes = 0);

/**
 * 交易在进入内存池mempool，进入验证区块前都需要验证
 * coinbase，coinstake不能进入内存池
 * 其他交易验证步骤：
 * 1.先检检验交易类型，使用IsLegalTxType，只有开放的交易类型才能通过验证
 * 2.通过交易的输出检验一些规格，比如通过输出数量，输出类型判断交易是否正确
 * 3.拿到输入，检测输入资产类型，输入数量，以及输入输出资产总量，手续费，负载信息等
 */

/** The basic transaction that is broadcasted on the network and contained in
 *  blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
public:
    static const int CURRENT_VERSION = 1;
    int nTypeAndVer; // 前两个字节表示交易类型，后两个字节表示版本号
    unsigned int nTime;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    unsigned int nLockTime;

    /**
     * 1.存储：保存在区块链使用base64编码数据，保存在本地数据库无需编码
     * 2.收费：根据编码后的长度计算
     * 3.判断合理：1)区块链底层：每个payload长度，以及总长度，都做编码后长度限制 2)前端界面：对资产英文名，资产符号，地址别名额外做明文字符长度限制，这个限制应该满足区块链底层限制
     */
    std::vector<std::string> vPayload;

    // Denial-of-service detection:
    mutable int nDoS;
    bool DoS(int nDoSIn, bool fIn) const { nDoS += nDoSIn; return fIn; }

    // icochain: 增加或修改交易类型时，需要修改IsLegalTxType函数 和 IsLegalTxFormat 函数
    // icochain: 定义交易类型标志，所有的交易都要标志类型
    enum
    {
        TX_TYPE_NULL           = 0, // 无类型
        TX_TYPE_COINBASE       = 1, // Coinbase
        TX_TYPE_COINSTAKE      = 2, // Coinstake
        TX_TYPE_TRANSFER_ZERO  = 3, // 小企股转账交易（输入和输出都只能是小企股）
        TX_TYPE_REGISTER_ASSET = 4, // 用户发行新资产
        TX_TYPE_TRANSFER_ASSET = 5, // 资产（用户发行）转账，需要小企股作为手续费
        TX_TYPE_EXCHANGE_ASSET = 6, // 新资产（用户发行）和小企股兑换（去中心化交易平台）
        TX_TYPE_REGISTER_ALIAS = 7, // 别名注册
        TX_TYPE_SEO_ASSET      = 8, // 增发资产
        TX_TYPE_TRANSFER_ALIAS = 9, // 转让别名
    };

    CTransaction()
    {
        SetNull();
    }

    CTransaction(int nType, int nVersion, unsigned int nTime, const std::vector<CTxIn>& vin, const std::vector<CTxOut>& vout, unsigned int nLockTime)
        :nTime(nTime), vin(vin), vout(vout), nLockTime(nLockTime), nDoS(0)
    {
        setTxType(nType);
        setTxVersion(nVersion);
        vPayload.clear();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nTypeAndVer);
        nVersion = this->getTxVersion();
        READWRITE(nTime);
        READWRITE(vin);
        READWRITE(vout);
        READWRITE(nLockTime);
        READWRITE(vPayload);
    )

    // icochain: 编码后存到区块链
    bool SetPayload(const std::string& payload);
    bool GetPayload(std::string& payload, int index=0) const;
    // icochain: 编码后的长度
    int  GetPayloadLength() const;
    // icochain: 在CheckTransaction 里调用，几种检测所有交易类型的信息负载
    bool CheckPayload() const;

    // icochain: 只用于注册新资产交易
    bool SetAssetPayload(const std::string& engName,const std::string& secondName,const std::string& symbol,const std::string& assetIntro);
    bool GetAssetPayload(std::string& engName,std::string& secondName,std::string& symbol,std::string& assetIntro) const;

    // icochain: 获取资产注册信息，如果是可增发资产，返回总量值是注册时的发行量
    int64_t GetAssetRegisterInfo(std::string& engName,std::string& secondName,std::string& symbol,std::string& assetIntro, std::string& publisher, int64_t &supply, int &suffix) const;

    // icochain: 只用于注册别名交易
    bool SetAliasPayload(const std::string& alias);
    bool GetAliasPayloadInfo(std::string& alias, std::string& address) const;

    // icochain: 计算交易各种费用，交易的输入、输出差额包含注册费，信息费，捐赠激励池数额以及交易手续费（sizefee）
    int64_t GetRegisterFee() const;
    int64_t GetPayloadFee() const;
    int64_t GetPowDonation() const;
    int64_t GetPosDonation() const;
    int64_t GetTotalDonation() const;

    // icochain: 注册费，信息费，捐赠激励池数额为非手续费差额
    int64_t GetNotSizeFeeChange() const;

    // icochain: 获取交易涉及的资产Id，有两种情况：一笔交易要么只处理小企股，此时返回小企股Id 0；要么是处理小企股和另一种用户发行资产，返回用户资产Id
    int64_t GetAssetId() const;

    void setTxVersion(int nVersionIn) // icochain: 后两个字节代表版本
    {
        assert((nVersionIn > 0) && (nVersionIn <= 0xffff));
        nTypeAndVer = (nTypeAndVer & 0xffff0000) | (nVersionIn & 0xffff);
    }

    int getTxVersion() const
    {
        return nTypeAndVer & 0xffff;
    }

    void setTxType(int nTxType) // icochain: 前两个字节代表交易类型
    {
        assert((nTxType >= 0) && (nTxType <= 0xffff));
        nTypeAndVer = (nTxType << 16) | (nTypeAndVer & 0xffff);
    }
    int getTxType() const
    {
        return (nTypeAndVer & 0xffff0000) >> 16;
    }

    void SetNull()
    {
        setTxType(TX_TYPE_NULL);
        setTxVersion(CTransaction::CURRENT_VERSION);
        nTime = GetAdjustedTime();
        vin.clear();
        vout.clear();
        nLockTime = 0;
        nDoS = 0;  // Denial-of-service prevention
        vPayload.clear();
    }

    bool IsNull() const
    {
        return (vin.empty() && vout.empty());
    }

    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }

    // icochain: 统计输出的资产类型总量
    int GetOutAssetIdCount() const
    {
        std::set<int> setIDs;
        setIDs.clear();
        BOOST_FOREACH(const CTxOut& txout, vout)
        {
            if(!setIDs.count(txout.nAssetId))
                setIDs.insert(txout.nAssetId);
        }
        return setIDs.size();
    }

    /** icochain: Coinbase交易
     *  要保证所有输出是小企股
     */
    bool IsCoinBase() const
    {
        if(getTxType() != TX_TYPE_COINBASE)
            return false;

        if(!vPayload.empty())
            return false;

        BOOST_FOREACH(const CTxOut& txout, vout)
        {
            if (txout.nAssetId != 0)
                return false;
        }

        return (vin.size() == 1 && vin[0].prevout.IsNull() && vout.size() >= 1);
    }

    /** icochain: Coinstake交易
     *  要保证所有输入输出是小企股
     */
    bool IsCoinStake() const
    {
        if(getTxType() != TX_TYPE_COINSTAKE)
            return false;
        if(!vPayload.empty())
            return false;

        BOOST_FOREACH(const CTxOut& txout, vout)
        {
            if (txout.nAssetId != 0)
                return false;
        }
        // ppcoin: the coin stake transaction is marked with the first output empty
        return (vin.size() > 0 && (!vin[0].prevout.IsNull()) && vout.size() >= 2 && vout[0].IsEmpty());
    }

    /** icochain: 小企股转账
     *  输出都是小企股
     *  输入也要求都是小企股（在验证交易时需要判断）
     */
    bool IsTransferZeroTx() const
    {
        if(getTxType() != TX_TYPE_TRANSFER_ZERO)
            return false;

        BOOST_FOREACH(const CTxOut& txout, vout)
        {
            if (txout.nAssetId != 0)
                return false;
        }

        return (vin.size() > 0 && vout.size() > 0 && vPayload.size() < 2 );
    }

    /** icochain: 捐赠激励池交易
     *  必须是转账小企股交易，所有的输入输出都是小企股
     *  捐赠数量和捐赠池子类型记录在payload里，vPayload有两个情况：
     *  1.size为2时，无用户留言信息，vPayload[0]记录捐赠池子类型，取值为"pow"或"pos"，vPayload[1]记录捐赠的数量，单位为COIN
     *  2.size为3时，有用户留言信息，vPayload[0]为用户留言，vPayload[1]记录捐赠池子类型，取值为"pow"或"pos"，vPayload[2]记录捐赠的数量，单位为COIN
     *  标记激励池类型和捐赠数额的两个payload不收取信息费，只有用户留言才收取信息费，但受payload总长度限制
     *  捐赠额只能是COIN的整倍数
     */
    bool IsDonationTx() const
    {
        if(getTxType() != TX_TYPE_TRANSFER_ZERO)
            return false;

        if (vPayload.size() != 2 && vPayload.size() != 3)
            return false;

        BOOST_FOREACH(const CTxOut& txout, vout)
        {
            if (txout.nAssetId != 0)
                return false;
        }

        return (vin.size() > 0 && vout.size() > 0);
    }

    /** icochain: 注册新资产交易
     *  用小企股作为手续费，假如发行的资产id为K，则；
     *  输入必须都是小企股
     *  输出数量最多有2个：
     *  第1个输出为新发型的资产
     *  第2个输出（找零，如果存在）是小企股
     */
    bool IsRegisterAssetTx() const
    {
        if(getTxType() != TX_TYPE_REGISTER_ASSET)
            return false;

        if (vin.size() <= 0 || vout.size() <= 0 || vout.size() > 2)
            return false;

        if(vout[0].IsNull() || vout[0].IsEmpty())
            return false;

        if(vout[0].nAssetId <= 0) //新资产id
            return false;

        //以后升级时要根据交易版本判断
        int nSuffix = vout[0].nAssetId % 100;
        if(nSuffix > 3)
            return false;

        if(vout[0].nValue <= 0) //新资产发行总量
            return false;

        if(vout.size() == 2 && vout[1].nAssetId != 0)
            return false;

        if(vPayload.size() != 4)
            return false;

        return true;
    }

    /** icochain: 增发资产交易
     *  用小企股作为手续费，资产必须是可增发类型；
     *  输入必须都是小企股，且必须有发行者地址
     *  输出数量最多有2个：
     *  第1个输出为增发的资产
     *  第2个输出（找零，如果存在）是小企股
     */
    bool IsSeoAssetTx() const
    {
        if(getTxType() != TX_TYPE_SEO_ASSET)
            return false;

        if (vin.size() <= 0 || vout.size() <= 0 || vout.size() > 2)
            return false;

        if(vout[0].IsNull() || vout[0].IsEmpty())
            return false;

        if(vout[0].nAssetId <= 0) // 新资产id
            return false;

        // 以后升级时要根据交易版本判断
        int nSuffix = vout[0].nAssetId % 100;
        if((nSuffix != 1) && (nSuffix != 2))
            return false;

        if(vout.size() == 2 && vout[1].nAssetId != 0)
            return false;

        if(vPayload.size() > 1)
            return false;

        return true;
    }

    /** icochain: 资产交易，每次只能交易一种资产，用小企股作为手续费，假如交易资产id为K，则：
     *  输入>=2,输入必须且只能有两种资产：0号和目标资产，两者都可以有多个输入；（在验证交易时需要做判断）
     *  输出>=1,且第一个输出为小企股(找零)或者k（没有找零）,其他输出必须都是k资产
     *  此外要求输入输出资产数量必须相等
     */
    bool IsTransferAssetTx() const
    {
        if(getTxType() != TX_TYPE_TRANSFER_ASSET)
            return false;
        if(vPayload.size() > 1)
            return false;

        int nOutSize = vout.size();
        int nOutIdCount = GetOutAssetIdCount();

        if (vin.size() < 2 || nOutSize < 1 || nOutIdCount < 1 || nOutIdCount > 2)
            return false;

        if(vout[0].nAssetId == 0) // 找零，第一个输出是小企股，其他都是同类非小企股
        {
            if(vout.size() < 2 || nOutIdCount != 2 )
                return false;
            for(int k = 1; k < nOutSize; k++)
            {
                if(vout[k].nAssetId == 0)
                    return false;
            }
        }
        else // 没有找零，所有输出都是同类资产
        {
            if(nOutIdCount != 1 )
                return false;
        }

        return true;
    }

    bool IsExchangeAssetTx() const // icochain: 未定义
    {
        return false;
    }

    /** icochain: 别名注册，用小企股作为手续费，则；
     *  输入必须都是小企股
     *  输出数量最多有2个，且都是小企股：
     *  第1个输出为注册的地址
     *  第2个输出（找零，如果存在）
     */
    bool IsRegisterAliasTx() const
    {
        if(getTxType() != TX_TYPE_REGISTER_ALIAS)
            return false;

        if (vin.size() <= 0 || vout.size() <= 0 || vout.size() > 2)
            return false;

        if(vout[0].IsNull() || vout[0].IsEmpty())
            return false;

        BOOST_FOREACH(const CTxOut& txout, vout)
        {
            if (txout.nAssetId != 0)
                return false;
        }

        if(vPayload.size() != 1)
            return false;

        return true;
    }

    /** icochain: 转让别名，用小企股作为手续费，则；
     *  输入必须都是小企股，第一个输入必须为别名原来的绑定地址
     *  输出数量最多有2个，且都是小企股：
     *  第1个输出为新绑定的地址
     *  第2个输出（找零，如果存在）
     *  payload只能有一个，即别名
     * */
    bool IsTransferAliasTx() const
    {
        if(getTxType() != TX_TYPE_TRANSFER_ALIAS)
            return false;

        if (vin.size() <= 0 || vout.size() <= 0 || vout.size() > 2)
            return false;

        if(vout[0].IsNull() || vout[0].IsEmpty())
            return false;

        BOOST_FOREACH(const CTxOut& txout, vout)
        {
            if (txout.nAssetId != 0)
                return false;
        }

        if(vPayload.size() != 1)
            return false;

        return true;
    }

    bool IsLegalTxType() const // 增加交易类型时，需要修改这个地方
    {
        switch (getTxType()) {
        case TX_TYPE_COINBASE: // coinbase
        case TX_TYPE_COINSTAKE: // coinstake
        case TX_TYPE_TRANSFER_ZERO: // 小企股转账
        case TX_TYPE_TRANSFER_ASSET: // 用户发行的资产转账
        case TX_TYPE_REGISTER_ASSET: // 发行新资产
        case TX_TYPE_REGISTER_ALIAS: // 别名注册
        case TX_TYPE_SEO_ASSET: // 增发资产
        case TX_TYPE_TRANSFER_ALIAS: // 转让别名
            return true;
        }

        return false;
    }

    // 第一版本交易只开放这指定的四种ID后缀:00 01 02 03
    bool IsLegalAssetId() const
    {
        BOOST_FOREACH(const CTxOut& txout, vout)
        {
            int suffix = txout.nAssetId % 100;

            if (suffix >= 4)
                return false;
        }

        return true;
    }

    bool IsLegalTxFormat() const
    {
        switch (getTxType()) {
        case TX_TYPE_COINBASE: // coinbase
            return IsCoinBase();

        case TX_TYPE_COINSTAKE: // coinstake
            return IsCoinStake();

        case TX_TYPE_TRANSFER_ZERO: // 小企股转账
            return IsTransferZeroTx();

        case TX_TYPE_REGISTER_ASSET: // 注册资产
            return IsRegisterAssetTx();

        case TX_TYPE_TRANSFER_ASSET: // 用户发行的资产转账
            return IsTransferAssetTx();

        case TX_TYPE_EXCHANGE_ASSET: // 资产兑换
            return IsExchangeAssetTx();

        case TX_TYPE_REGISTER_ALIAS: // 注册别名
            return IsRegisterAliasTx();

        case TX_TYPE_SEO_ASSET: // 增发资产
            return IsSeoAssetTx();

        case TX_TYPE_TRANSFER_ALIAS: // 转让别名
            return IsTransferAliasTx();

        default:
            return false;
        }
        return false;
    }


    /** Amount of bitcoins spent by this transaction.
        @return sum of all outputs (note: does not include fees)
     */
    int64_t GetValueOut(int64_t nAssetId) const // icochain: 计算特定资产的总输出额
    {
        int64_t nValueOut = 0;
        BOOST_FOREACH(const CTxOut& txout, vout)
        {
            if(txout.nAssetId == nAssetId)
            {
                nValueOut += txout.nValue;
                if (!MoneyRange(txout.nValue) || !MoneyRange(nValueOut))
                    throw std::runtime_error("CTransaction::GetValueOut() : value out of range");
            }
        }
        return nValueOut;
    }


    /** Amount of bitcoins coming in to this transaction
        Note that lightweight clients may not know anything besides the hash of previous transactions,
        so may not be able to calculate this.

        @param[in] mapInputs	Map of previous transactions that have outputs we're spending
        @return	Sum of value of all inputs (scriptSigs)
        @see CTransaction::FetchInputs
     */
    int64_t GetValueIn(int64_t nAssetId, const MapPrevTx& mapInputs) const;

    // 检测交易的输入输出，包括检测手续费，输入输出资产类型，输入输出资产总量
    bool CheckIoValue(MapPrevTx& mapInputs) const;


    bool ReadFromDisk(CDiskTxPos pos, FILE** pfileRet=NULL)
    {
        CAutoFile filein = CAutoFile(OpenBlockFile(pos.nFile, 0, pfileRet ? "rb+" : "rb"), SER_DISK, CLIENT_VERSION);
        if (!filein)
            return error("CTransaction::ReadFromDisk() : OpenBlockFile failed");

        // Read transaction
        if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
            return error("CTransaction::ReadFromDisk() : fseek failed");

        try {
            filein >> *this;
        }
        catch (std::exception &e) {
            return error("%s() : deserialize or I/O error", __PRETTY_FUNCTION__);
        }

        // Return file pointer
        if (pfileRet)
        {
            if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
                return error("CTransaction::ReadFromDisk() : second fseek failed");
            *pfileRet = filein.release();
        }
        return true;
    }

    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return (a.nTypeAndVer  == b.nTypeAndVer &&
                a.nTime     == b.nTime &&
                a.vin       == b.vin &&
                a.vout      == b.vout &&
                a.nLockTime == b.nLockTime&&
                a.vPayload == b.vPayload);
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return !(a == b);
    }

    std::string GetTxTypeString() const
    {
        switch (getTxType()) {
        case TX_TYPE_COINBASE: // coinbase
            return "TX_TYPE_COINBASE";

        case TX_TYPE_COINSTAKE: // coinstake
            return "TX_TYPE_COINSTAKE";

        case TX_TYPE_TRANSFER_ZERO: // 小企股转账
            return "TX_TYPE_TRANSFER_ZERO";

        case TX_TYPE_REGISTER_ASSET: // 发行新资产
            return "TX_TYPE_REGISTER_ASSET";

        case TX_TYPE_SEO_ASSET: // 发行新资产
            return "TX_TYPE_SEO_ASSET";

        case TX_TYPE_TRANSFER_ASSET: // 用户发行的资产转账
            return "TX_TYPE_TRANSFER_ASSET";

        case TX_TYPE_EXCHANGE_ASSET: // 资产兑换
            return "TX_TYPE_EXCHANGE_ASSET";

        case TX_TYPE_REGISTER_ALIAS: // 别名注册
            return "TX_TYPE_REGISTER_ALIAS";

        case TX_TYPE_TRANSFER_ALIAS: // 转让别名
            return "TX_TYPE_TRANSFER_ALIAS";

        default:
            return "ERROR";
        }
    }

    std::string PayloadToString() const
    {
        std::string strRes;
        strRes.clear();
        for(int i = 0 ; i < vPayload.size() ; i++)
        {
            std::string str;
            GetPayload(str,i);
            strRes += (str + "\n");
        }
        return strRes;
    }

    std::string ToString() const
    {
        std::string str;
        str += IsCoinBase()? "Coinbase" : (IsCoinStake()? "Coinstake" : "CTransaction");
        str += strprintf("(hash=%s, nTime=%d, type=%d(%s), version=%d, vin.size=%u, vout.size=%u, nLockTime=%d)\n",
            GetHash().ToString(),
            nTime,
            getTxType(),
            GetTxTypeString(),
            getTxVersion(),
            vin.size(),
            vout.size(),
            nLockTime);

        for (unsigned int i = 0; i < vin.size(); i++)
            str += "    " + vin[i].ToString() + "\n";
        for (unsigned int i = 0; i < vout.size(); i++)
            str += "    " + vout[i].ToString() + "\n";

        str += "vPayload:" + (PayloadToString() + "\n" );
        return str;
    }


    bool ReadFromDisk(CTxDB& txdb, COutPoint prevout, CTxIndex& txindexRet);
    bool ReadFromDisk(CTxDB& txdb, COutPoint prevout);
    bool ReadFromDisk(COutPoint prevout);
    bool DisconnectInputs(CTxDB& txdb);

    /** Fetch from memory and/or disk. inputsRet keys are transaction hashes.

     @param[in] txdb	Transaction database
     @param[in] mapTestPool	List of pending changes to the transaction index database
     @param[in] fBlock	True if being called to add a new best-block to the chain
     @param[in] fMiner	True if being called by CreateNewBlock
     @param[out] inputsRet	Pointers to this transaction's inputs
     @param[out] fInvalid	returns true if transaction is invalid
     @return	Returns true if all inputs are in txdb or mapTestPool
     */
    bool FetchInputs(CTxDB& txdb, const std::map<uint256, CTxIndex>& mapTestPool,
                     bool fBlock, bool fMiner, MapPrevTx& inputsRet, bool& fInvalid);

    /** Sanity check previous transactions, then, if all checks succeed,
        mark them as spent by this transaction.

        @param[in] inputs	Previous transactions (from FetchInputs)
        @param[out] mapTestPool	Keeps track of inputs that need to be updated on disk
        @param[in] posThisTx	Position of this transaction on disk
        @param[in] pindexBlock
        @param[in] fBlock	true if called from ConnectBlock
        @param[in] fMiner	true if called from CreateNewBlock
        @return Returns true if all checks succeed
     */
    bool ConnectInputs(CTxDB& txdb, MapPrevTx inputs,
                       std::map<uint256, CTxIndex>& mapTestPool, const CDiskTxPos& posThisTx,
                       const CBlockIndex* pindexBlock, bool fBlock, bool fMiner, unsigned int flags = STANDARD_SCRIPT_VERIFY_FLAGS);
    bool CheckTransaction() const;
    bool GetCoinAge(CTxDB& txdb, const CBlockIndex* pindexPrev, uint64_t& nCoinAge) const;

    const CTxOut& GetOutputFor(const CTxIn& input, const MapPrevTx& inputs) const;
};

/** wrapper for CTxOut that provides a more compact serialization */
class CTxOutCompressor
{
private:
    CTxOut &txout;
public:
    CTxOutCompressor(CTxOut &txoutIn) : txout(txoutIn) { }

    IMPLEMENT_SERIALIZE(
        READWRITE(txout.nAssetId);
        READWRITE(VARINT(txout.nValue));
        CScriptCompressor cscript(REF(txout.scriptPubKey));
        READWRITE(cscript);
    )
};

/** Check for standard transaction types
    @param[in] mapInputs	Map of previous transactions that have outputs we're spending
    @return True if all inputs (scriptSigs) use only standard transaction forms
    @see CTransaction::FetchInputs
*/
bool AreInputsStandard(const CTransaction& tx, const MapPrevTx& mapInputs);

/** Count ECDSA signature operations the old-fashioned (pre-0.6) way
    @return number of sigops this transaction's outputs will produce when spent
    @see CTransaction::FetchInputs
*/
unsigned int GetLegacySigOpCount(const CTransaction& tx);

/** Count ECDSA signature operations in pay-to-script-hash inputs.

    @param[in] mapInputs	Map of previous transactions that have outputs we're spending
    @return maximum number of sigops required to validate this transaction's inputs
    @see CTransaction::FetchInputs
 */
unsigned int GetP2SHSigOpCount(const CTransaction& tx, const MapPrevTx& mapInputs);

/** Check for standard transaction types
    @return True if all outputs (scriptPubKeys) use only standard transaction forms
*/
bool IsStandardTx(const CTransaction& tx, std::string& reason);

bool IsFinalTx(const CTransaction &tx, int nBlockHeight = 0, int64_t nBlockTime = 0);



/** A transaction with a merkle branch linking it to the block chain. */
class CMerkleTx : public CTransaction
{
private:
    int GetDepthInMainChainINTERNAL(CBlockIndex* &pindexRet) const;
public:
    uint256 hashBlock;
    std::vector<uint256> vMerkleBranch;
    int nIndex;

    // memory only
    mutable bool fMerkleVerified;


    CMerkleTx()
    {
        Init();
    }

    CMerkleTx(const CTransaction& txIn) : CTransaction(txIn)
    {
        Init();
    }

    void Init()
    {
        hashBlock = 0;
        nIndex = -1;
        fMerkleVerified = false;
    }


    IMPLEMENT_SERIALIZE
    (
        nSerSize += SerReadWrite(s, *(CTransaction*)this, nType, nVersion, ser_action);
        nVersion = this->getTxVersion();
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    )


    int SetMerkleBranch(const CBlock* pblock=NULL);

    // Return depth of transaction in blockchain:
    // -1  : not in blockchain, and not in memory pool (conflicted transaction)
    //  0  : in memory pool, waiting to be included in a block
    // >=1 : this many blocks deep in the main chain
    int GetDepthInMainChain(CBlockIndex* &pindexRet) const;
    int GetDepthInMainChain() const { CBlockIndex *pindexRet; return GetDepthInMainChain(pindexRet); }
    bool IsInMainChain() const { CBlockIndex *pindexRet; return GetDepthInMainChainINTERNAL(pindexRet) > 0; }
    int GetBlocksToMaturity() const;
    bool AcceptToMemoryPool(bool fLimitFree=true);
};




/**  A txdb record that contains the disk location of a transaction and the
 * locations of transactions that spend its outputs.  vSpent is really only
 * used as a flag, but having the location is very helpful for debugging.
 */
class CTxIndex
{
public:
    CDiskTxPos pos;
    std::vector<CDiskTxPos> vSpent;

    CTxIndex()
    {
        SetNull();
    }

    CTxIndex(const CDiskTxPos& posIn, unsigned int nOutputs)
    {
        pos = posIn;
        vSpent.resize(nOutputs);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(pos);
        READWRITE(vSpent);
    )

    void SetNull()
    {
        pos.SetNull();
        vSpent.clear();
    }

    bool IsNull()
    {
        return pos.IsNull();
    }

    friend bool operator==(const CTxIndex& a, const CTxIndex& b)
    {
        return (a.pos    == b.pos &&
                a.vSpent == b.vSpent);
    }

    friend bool operator!=(const CTxIndex& a, const CTxIndex& b)
    {
        return !(a == b);
    }
    int GetDepthInMainChain() const;

};





/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 *
 * Blocks are appended to blk0001.dat files on disk.  Their location on disk
 * is indexed by CBlockIndex objects in memory.
 */
class CBlock
{
public:
    // header
    static const int CURRENT_VERSION = 1;
    int nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;

    // network and disk
    std::vector<CTransaction> vtx;

    // ppcoin: block signature - signed by one of the coin base txout[N]'s owner
    std::vector<unsigned char> vchBlockSig;

    // memory only
    mutable std::vector<uint256> vMerkleTree;

    // Denial-of-service detection:
    mutable int nDoS;
    bool DoS(int nDoSIn, bool fIn) const { nDoS += nDoSIn; return fIn; }

    CBlock()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);

        // ConnectBlock depends on vtx following header to generate CDiskTxPos
        if (!(nType & (SER_GETHASH|SER_BLOCKHEADERONLY)))
        {
            READWRITE(vtx);
            READWRITE(vchBlockSig);
        }
        else if (fRead)
        {
            const_cast<CBlock*>(this)->vtx.clear();
            const_cast<CBlock*>(this)->vchBlockSig.clear();
        }
    )

    void SetNull()
    {
        nVersion = CBlock::CURRENT_VERSION;
        hashPrevBlock = 0;
        hashMerkleRoot = 0;
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        vtx.clear();
        vchBlockSig.clear();
        vMerkleTree.clear();
        nDoS = 0;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const
    {
        return GetPoWHash();
    }

    uint256 GetPoWHash() const
    {
        return IHash(BEGIN(nVersion), END(nNonce));
    }

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    void UpdateTime(const CBlockIndex* pindexPrev);

    // entropy bit for stake modifier if chosen by modifier
    unsigned int GetStakeEntropyBit() const
    {
        // Take last bit of block hash as entropy bit
        unsigned int nEntropyBit = ((GetHash().GetLow64()) & 1llu);
        LogPrint("stakemodifier", "GetStakeEntropyBit: hashBlock=%s nEntropyBit=%u\n", GetHash().ToString(), nEntropyBit);
        return nEntropyBit;
    }

    // ppcoin: two types of block: proof-of-work or proof-of-stake
    bool IsProofOfStake() const
    {
        return (vtx.size() > 1 && vtx[1].IsCoinStake());
    }

    bool IsProofOfWork() const
    {
        return !IsProofOfStake();
    }

    std::pair<COutPoint, unsigned int> GetProofOfStake() const
    {
        return IsProofOfStake()? std::make_pair(vtx[1].vin[0].prevout, vtx[1].nTime) : std::make_pair(COutPoint(), (unsigned int)0);
    }

    // ppcoin: get max transaction timestamp
    int64_t GetMaxTransactionTime() const
    {
        int64_t maxTransactionTime = 0;
        BOOST_FOREACH(const CTransaction& tx, vtx)
            maxTransactionTime = std::max(maxTransactionTime, (int64_t)tx.nTime);
        return maxTransactionTime;
    }

    uint256 BuildMerkleTree() const
    {
        vMerkleTree.clear();
        BOOST_FOREACH(const CTransaction& tx, vtx)
            vMerkleTree.push_back(tx.GetHash());
        int j = 0;
        for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
        {
            for (int i = 0; i < nSize; i += 2)
            {
                int i2 = std::min(i+1, nSize-1);
                vMerkleTree.push_back(Hash(BEGIN(vMerkleTree[j+i]),  END(vMerkleTree[j+i]),
                                           BEGIN(vMerkleTree[j+i2]), END(vMerkleTree[j+i2])));
            }
            j += nSize;
        }
        return (vMerkleTree.empty() ? 0 : vMerkleTree.back());
    }

    std::vector<uint256> GetMerkleBranch(int nIndex) const
    {
        if (vMerkleTree.empty())
            BuildMerkleTree();
        std::vector<uint256> vMerkleBranch;
        int j = 0;
        for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
        {
            int i = std::min(nIndex^1, nSize-1);
            vMerkleBranch.push_back(vMerkleTree[j+i]);
            nIndex >>= 1;
            j += nSize;
        }
        return vMerkleBranch;
    }

    static uint256 CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex)
    {
        if (nIndex == -1)
            return 0;
        BOOST_FOREACH(const uint256& otherside, vMerkleBranch)
        {
            if (nIndex & 1)
                hash = Hash(BEGIN(otherside), END(otherside), BEGIN(hash), END(hash));
            else
                hash = Hash(BEGIN(hash), END(hash), BEGIN(otherside), END(otherside));
            nIndex >>= 1;
        }
        return hash;
    }


    bool WriteToDisk(unsigned int& nFileRet, unsigned int& nBlockPosRet)
    {
        // Open history file to append
        CAutoFile fileout = CAutoFile(AppendBlockFile(nFileRet), SER_DISK, CLIENT_VERSION);
        if (!fileout)
            return error("CBlock::WriteToDisk() : AppendBlockFile failed");

        // Write index header
        unsigned int nSize = fileout.GetSerializeSize(*this);
        fileout << FLATDATA(Params().MessageStart()) << nSize;

        // Write block
        long fileOutPos = ftell(fileout);
        if (fileOutPos < 0)
            return error("CBlock::WriteToDisk() : ftell failed");
        nBlockPosRet = fileOutPos;
        fileout << *this;

        // Flush stdio buffers and commit to disk before returning
        fflush(fileout);
        if (!IsInitialBlockDownload() || (nBestHeight+1) % 500 == 0)
            FileCommit(fileout);

        return true;
    }

    bool ReadFromDisk(unsigned int nFile, unsigned int nBlockPos, bool fReadTransactions=true)
    {
        SetNull();

        // Open history file to read
        CAutoFile filein = CAutoFile(OpenBlockFile(nFile, nBlockPos, "rb"), SER_DISK, CLIENT_VERSION);
        if (!filein)
            return error("CBlock::ReadFromDisk() : OpenBlockFile failed");
        if (!fReadTransactions)
            filein.nType |= SER_BLOCKHEADERONLY;

        // Read block
        try {
            filein >> *this;
        }
        catch (std::exception &e) {
            return error("%s() : deserialize or I/O error", __PRETTY_FUNCTION__);
        }

        // Check the header
        if (fReadTransactions && IsProofOfWork() && !CheckProofOfWork(GetPoWHash(), nBits))
            return error("CBlock::ReadFromDisk() : errors in block header");

        return true;
    }



    std::string ToString() const
    {
        std::stringstream s;
        s << strprintf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u, vchBlockSig=%s)\n",
            GetHash().ToString(),
            nVersion,
            hashPrevBlock.ToString(),
            hashMerkleRoot.ToString(),
            nTime, nBits, nNonce,
            vtx.size(),
            HexStr(vchBlockSig.begin(), vchBlockSig.end()));
        for (unsigned int i = 0; i < vtx.size(); i++)
        {
            s << "  " << vtx[i].ToString() << "\n";
        }
        s << "  vMerkleTree: ";
        for (unsigned int i = 0; i < vMerkleTree.size(); i++)
            s << " " << vMerkleTree[i].ToString();
        s << "\n";
        return s.str();
    }


    bool DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex);
    bool ConnectBlock(CTxDB& txdb, CBlockIndex* pindex, bool fJustCheck=false);
    bool ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions=true);
    bool SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew);
    bool AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos, const uint256& hashProof);
    bool CheckBlock(bool fCheckPOW=true, bool fCheckMerkleRoot=true, bool fCheckSig=true) const;
    bool AcceptBlock();
    bool SignBlock(CWallet& keystore, int64_t nFees, int64_t pPosIncPool);
    bool CheckBlockSignature() const;

private:
    bool SetBestChainInner(CTxDB& txdb, CBlockIndex *pindexNew);
};






/** The block chain is a tree shaped structure starting with the
 * genesis block at the root, with each block potentially having multiple
 * candidates to be the next block.  pprev and pnext link a path through the
 * main/longest chain.  A  may have multiple pprev pointing back
 * to it, but pnext will only point forward to the longest branch, or will
 * be null if the block is not part of the longest chain.
 */
class CBlockIndex
{
public:
    const uint256* phashBlock;
    CBlockIndex* pprev;
    CBlockIndex* pnext;
    unsigned int nFile;
    unsigned int nBlockPos;
    uint256 nChainTrust; // ppcoin: trust score of block chain
    int nHeight;
    int nPowHeight; // icochain: POW区块高度

    int nAssetTypeCount; // icochain: 资产类型数量

    int64_t nPowIncentivePool; // icochain: POW激励池
    int64_t nPosIncentivePool; // icochain: POS激励池

    int64_t nMint;
    int64_t nMoneySupply;

    unsigned int nFlags;  // ppcoin: block index flags
    enum  
    {
        BLOCK_PROOF_OF_STAKE = (1 << 0), // is proof-of-stake block
        BLOCK_STAKE_ENTROPY  = (1 << 1), // entropy bit for stake modifier
        BLOCK_STAKE_MODIFIER = (1 << 2), // regenerated stake modifier
    };

    uint64_t nStakeModifier; // hash modifier for proof-of-stake
    uint256 bnStakeModifierV2;

    // proof-of-stake specific fields
    COutPoint prevoutStake;
    unsigned int nStakeTime;

    uint256 hashProof;

    // block header
    int nVersion;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;

    CBlockIndex()
    {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;
        nFile = 0;
        nBlockPos = 0;
        nHeight = 0;
        nPowHeight = 0;
        nAssetTypeCount = 0;
        nPowIncentivePool = 0;
        nPosIncentivePool = 0;
        nChainTrust = 0;
        nMint = 0;
        nMoneySupply = 0;
        nFlags = 0;
        nStakeModifier = 0;
        bnStakeModifierV2 = 0;
        hashProof = 0;
        prevoutStake.SetNull();
        nStakeTime = 0;

        nVersion       = 0;
        hashMerkleRoot = 0;
        nTime          = 0;
        nBits          = 0;
        nNonce         = 0;
    }

    CBlockIndex(unsigned int nFileIn, unsigned int nBlockPosIn, CBlock& block)
    {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;
        nFile = nFileIn;
        nBlockPos = nBlockPosIn;
        nHeight = 0;
        nPowHeight = 0;
        nAssetTypeCount = 0;
        nPowIncentivePool = 0;
        nPosIncentivePool = 0;
        nChainTrust = 0;
        nMint = 0;
        nMoneySupply = 0;
        nFlags = 0;
        nStakeModifier = 0;
        bnStakeModifierV2 = 0;
        hashProof = 0;
        if (block.IsProofOfStake())
        {
            SetProofOfStake();
            prevoutStake = block.vtx[1].vin[0].prevout;
            nStakeTime = block.vtx[1].nTime;
        }
        else
        {
            prevoutStake.SetNull();
            nStakeTime = 0;
        }

        nVersion       = block.nVersion;
        hashMerkleRoot = block.hashMerkleRoot;
        nTime          = block.nTime;
        nBits          = block.nBits;
        nNonce         = block.nNonce;
    }

    CBlock GetBlockHeader() const
    {
        CBlock block;
        block.nVersion       = nVersion;
        if (pprev)
            block.hashPrevBlock = pprev->GetBlockHash();
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        return block;
    }

    uint256 GetBlockHash() const
    {
        return *phashBlock;
    }

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    uint256 GetBlockTrust() const;

    bool IsInMainChain() const
    {
        return (pnext || this == pindexBest);
    }

    bool CheckIndex() const
    {
        return true;
    }

    int64_t GetPastTimeLimit() const
    {
        return GetBlockTime();
    }

    enum { nMedianTimeSpan=11 };

    int64_t GetMedianTimePast() const
    {
        int64_t pmedian[nMedianTimeSpan];
        int64_t* pbegin = &pmedian[nMedianTimeSpan];
        int64_t* pend = &pmedian[nMedianTimeSpan];

        const CBlockIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
            *(--pbegin) = pindex->GetBlockTime();

        std::sort(pbegin, pend);
        return pbegin[(pend - pbegin)/2];
    }

    /**
     * Returns true if there are nRequired or more blocks of minVersion or above
     * in the last nToCheck blocks, starting at pstart and going backwards.
     */
    static bool IsSuperMajority(int minVersion, const CBlockIndex* pstart,
                                unsigned int nRequired, unsigned int nToCheck);


    bool IsProofOfWork() const
    {
        return !(nFlags & BLOCK_PROOF_OF_STAKE);
    }

    bool IsProofOfStake() const
    {
        return (nFlags & BLOCK_PROOF_OF_STAKE);
    }

    void SetProofOfStake()
    {
        nFlags |= BLOCK_PROOF_OF_STAKE;
    }

    unsigned int GetStakeEntropyBit() const
    {
        return ((nFlags & BLOCK_STAKE_ENTROPY) >> 1);
    }

    bool SetStakeEntropyBit(unsigned int nEntropyBit)
    {
        if (nEntropyBit > 1)
            return false;
        nFlags |= (nEntropyBit? BLOCK_STAKE_ENTROPY : 0);
        return true;
    }

    bool GeneratedStakeModifier() const
    {
        return (nFlags & BLOCK_STAKE_MODIFIER);
    }

    void SetStakeModifier(uint64_t nModifier, bool fGeneratedStakeModifier)
    {
        nStakeModifier = nModifier;
        if (fGeneratedStakeModifier)
            nFlags |= BLOCK_STAKE_MODIFIER;
    }

    std::string ToString() const
    {
        return strprintf("CBlockIndex(nHeight=%d, nPowHeight=%d, nTime=%u, assetTypes=%d, PowPool=%s, PosPool=%s, nMint=%s, nMoneySupply=%s, nFlags=(%s)(%d)(%s), nStakeModifier=%016x, hashProof=%s, nStakeTime=%d merkle=%s, hashBlock=%s)",
            nHeight, nPowHeight, nTime, nAssetTypeCount,
            FormatMoney(nPowIncentivePool).c_str(), FormatMoney(nPosIncentivePool).c_str(),
            FormatMoney(nMint).c_str(), FormatMoney(nMoneySupply).c_str(),
            GeneratedStakeModifier() ? "MOD" : "-", GetStakeEntropyBit(), IsProofOfStake()? "PoS" : "PoW",
            nStakeModifier,
            hashProof.ToString().c_str(),
            nStakeTime,
            hashMerkleRoot.ToString().c_str(),
            GetBlockHash().ToString().c_str());
    }
};



/** Used to marshal pointers into hashes for db storage. */
class CDiskBlockIndex : public CBlockIndex
{
private:
    uint256 blockHash;

public:
    uint256 hashPrev;
    uint256 hashNext;

    CDiskBlockIndex()
    {
        hashPrev = 0;
        hashNext = 0;
        blockHash = 0;
    }

    explicit CDiskBlockIndex(CBlockIndex* pindex) : CBlockIndex(*pindex)
    {
        hashPrev = (pprev ? pprev->GetBlockHash() : 0);
        hashNext = (pnext ? pnext->GetBlockHash() : 0);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);

        READWRITE(hashNext);
        READWRITE(nFile);
        READWRITE(nBlockPos);
        READWRITE(nHeight);
        READWRITE(nPowHeight);
        READWRITE(nAssetTypeCount);
        READWRITE(nPowIncentivePool);
        READWRITE(nPosIncentivePool);
        READWRITE(nMint);
        READWRITE(nMoneySupply);
        READWRITE(nFlags);
        READWRITE(nStakeModifier);
        READWRITE(bnStakeModifierV2);
        if (IsProofOfStake())
        {
            READWRITE(prevoutStake);
            READWRITE(nStakeTime);
        }
        else if (fRead)
        {
            const_cast<CDiskBlockIndex*>(this)->prevoutStake.SetNull();
            const_cast<CDiskBlockIndex*>(this)->nStakeTime = 0;
        }
        READWRITE(hashProof);

        // block header
        READWRITE(this->nVersion);
        READWRITE(hashPrev);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
        READWRITE(blockHash);
    )

    uint256 GetBlockHash() const
    {
        if (fUseFastIndex && (nTime < GetAdjustedTime() - 24 * 60 * 60) && blockHash != 0)
            return blockHash;

        CBlock block;
        block.nVersion        = nVersion;
        block.hashPrevBlock   = hashPrev;
        block.hashMerkleRoot  = hashMerkleRoot;
        block.nTime           = nTime;
        block.nBits           = nBits;
        block.nNonce          = nNonce;

       const_cast<CDiskBlockIndex*>(this)->blockHash = block.GetHash();
       return blockHash;
    }

    std::string ToString() const
    {
        std::string str = "CDiskBlockIndex(";
        str += CBlockIndex::ToString();
        str += strprintf("\n                hashBlock=%s, hashPrev=%s, hashNext=%s)",
            GetBlockHash().ToString(),
            hashPrev.ToString(),
            hashNext.ToString());
        return str;
    }
};








/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
class CBlockLocator
{
protected:
    std::vector<uint256> vHave;
public:

    CBlockLocator()
    {
    }

    explicit CBlockLocator(const CBlockIndex* pindex)
    {
        Set(pindex);
    }

    explicit CBlockLocator(uint256 hashBlock)
    {
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end())
            Set((*mi).second);
    }

    CBlockLocator(const std::vector<uint256>& vHaveIn)
    {
        vHave = vHaveIn;
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    )

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull()
    {
        return vHave.empty();
    }

    void Set(const CBlockIndex* pindex)
    {
        vHave.clear();
        int nStep = 1;
        while (pindex)
        {
            vHave.push_back(pindex->GetBlockHash());

            // Exponentially larger steps back
            for (int i = 0; pindex && i < nStep; i++)
                pindex = pindex->pprev;
            if (vHave.size() > 10)
                nStep *= 2;
        }
        vHave.push_back(Params().HashGenesisBlock());
    }

    int GetDistanceBack()
    {
        // Retrace how far back it was in the sender's branch
        int nDistance = 0;
        int nStep = 1;
        BOOST_FOREACH(const uint256& hash, vHave)
        {
            std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end())
            {
                CBlockIndex* pindex = (*mi).second;
                if (pindex->IsInMainChain())
                    return nDistance;
            }
            nDistance += nStep;
            if (nDistance > 10)
                nStep *= 2;
        }
        return nDistance;
    }

    CBlockIndex* GetBlockIndex()
    {
        // Find the first block the caller has in the main chain
        BOOST_FOREACH(const uint256& hash, vHave)
        {
            std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end())
            {
                CBlockIndex* pindex = (*mi).second;
                if (pindex->IsInMainChain())
                    return pindex;
            }
        }
        return pindexGenesisBlock;
    }

    uint256 GetBlockHash()
    {
        // Find the first block the caller has in the main chain
        BOOST_FOREACH(const uint256& hash, vHave)
        {
            std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end())
            {
                CBlockIndex* pindex = (*mi).second;
                if (pindex->IsInMainChain())
                    return hash;
            }
        }
        return Params().HashGenesisBlock();
    }

    int GetHeight()
    {
        CBlockIndex* pindex = GetBlockIndex();
        if (!pindex)
            return 0;
        return pindex->nHeight;
    }
};










class CWalletInterface {
protected:
    virtual void SyncTransaction(const CTransaction &tx, const CBlock *pblock, bool fConnect) =0;
    virtual void EraseFromWallet(const uint256 &hash) =0;
    virtual void SetBestChain(const CBlockLocator &locator) =0;
    virtual void UpdatedTransaction(const uint256 &hash) =0;
    virtual void Inventory(const uint256 &hash) =0;
    virtual void ResendWalletTransactions(bool fForce) =0;
    friend void ::RegisterWallet(CWalletInterface*);
    friend void ::UnregisterWallet(CWalletInterface*);
    friend void ::UnregisterAllWallets();
};

#endif
