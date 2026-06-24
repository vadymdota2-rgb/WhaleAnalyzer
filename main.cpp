#define CPPHTTPLIB_OPENSSL_SUPPORT
// ============================================================================
//  Analyzer Bot v1.1 FINAL - с дельтами индикаторов (3/15/60 свечей)
//  Compile: g++ -std=c++17 -O2 analyzer.cpp -o analyzer -lsqlite3 -lpthread -lssl -lcrypto
// ============================================================================

#include "httplib.h"
#include <nlohmann/json.hpp>
#include <sqlite3.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using json = nlohmann::json;
namespace fs = std::filesystem;

// ============================================================================
//  CONFIG
// ============================================================================
namespace cfg {

inline const std::string& getBotToken() {
    static const std::string token = []() -> std::string {
        const char* envVal = std::getenv("BOT_TOKEN");
        if (envVal && envVal[0] != '\0') {
            return std::string(envVal);
        }
        std::cerr << "[FATAL] BOT_TOKEN environment variable is not set.\n";
        std::exit(1);    }();
    return token;
}

const int64_t     SOURCE_CHANNEL   = -1003978563317LL;
const int64_t     OUTPUT_CHANNEL   = -1003978563317LL;
const int64_t     ADMIN_ID         = 123456789;

const std::vector<std::string> BSC_RPC = {
    "https://bsc-dataseed1.binance.org",
    "https://bsc-dataseed2.binance.org",
    "https://bsc-dataseed3.binance.org",
    "https://bsc-dataseed4.binance.org",
    "https://bsc.publicnode.com",
    "https://rpc.ankr.com/bsc"
};

const std::vector<std::string> STABLECOINS = {
    "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
    "0x55d398326f99059ff775485246999027b3197955",
    "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
    "0xe9e7cea3dedca5984780bafc599bd69add087d56",
    "0xc5f0f7b66764f6ec8c8dff7ba683102295e16409",
    "0xd17479997f34dd9156deef8f95a52d81d265be9c"
};

const std::string DEXSCREENER_BASE  = "https://api.dexscreener.com";
const std::string GECKO_BASE        = "https://api.geckoterminal.com";

const std::string DB_PATH = "analyzer.db";
const int CLEANUP_TRIGGER   = 200;
const int KEEP_LAST_TX      = 500;
const int POLL_TIMEOUT_SEC  = 30;
const int RSI_PERIOD        = 14;
const int MIN_OHLCV_FOR_1H  = 120;
const size_t MAX_LOG_SIZE_MB = 10;

const int HEALTH_TIMEOUT_MS = 1500;
const int MAINTENANCE_INTERVAL_HOURS = 24;

const int NUM_WORKER_THREADS = 3;
const size_t MAX_QUEUE_SIZE = 1000;

const int STALE_TASK_CHECK_INTERVAL_SEC = 120;
const int64_t STALE_TASK_TTL_SECONDS    = 600;
const int MAX_RECLAIM_ATTEMPTS = 5;
const int STALE_RECLAIMER_PUSH_TIMEOUT_MS = 3000;

const int WORKER_HEARTBEAT_CHECK_INTERVAL_SEC = 60;
const int64_t WORKER_HANG_TIMEOUT_SEC         = 900;const int MAX_WORKER_REPLACEMENTS_PER_SLOT = 10;

const int64_t HEALTH_COMMAND_COOLDOWN_SEC = 30;
const int64_t QUEUE_BLOCKED_WARN_MS = 5000;

} // namespace cfg

// ============================================================================
//  LOGGER
// ============================================================================
class Logger {
public:
    enum Level { INFO, WARN, ERR };

    static void log(Level lvl, const std::string& msg) {
        static std::mutex mtx;
        std::lock_guard<std::mutex> lk(mtx);
        checkAndRotate();

        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        char buf[32];
        
        struct tm tmBuf;
#if defined(_WIN32)
        localtime_s(&tmBuf, &t);
#else
        localtime_r(&t, &tmBuf);
#endif
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmBuf);
        const char* tag = lvl == INFO ? "INFO" : (lvl == WARN ? "WARN" : "ERR");

        std::ofstream f("logs/analyzer.log", std::ios::app);
        std::string line = std::string("[") + buf + "] [" + tag + "] " + msg;
        std::cerr << line << "\n";
        if (f) f << line << "\n";
    }

private:
    static void checkAndRotate() {
        static int checkCounter = 0;
        if (++checkCounter % 100 != 0) return;

        std::error_code ec;
        auto size = fs::file_size("logs/analyzer.log", ec);
        if (ec || size > cfg::MAX_LOG_SIZE_MB * 1024 * 1024) {
            rotate();
        }
    }
    static void rotate() {
        std::error_code ec;
        fs::remove("logs/analyzer.log.3", ec);
        fs::rename("logs/analyzer.log.2", "logs/analyzer.log.3", ec);
        fs::rename("logs/analyzer.log.1", "logs/analyzer.log.2", ec);
        fs::rename("logs/analyzer.log", "logs/analyzer.log.1", ec);
    }
};

#define LOG_INFO(m) Logger::log(Logger::INFO, m)
#define LOG_WARN(m) Logger::log(Logger::WARN, m)
#define LOG_ERR(m)  Logger::log(Logger::ERR,  m)

// ============================================================================
//  HTTP CLIENT
// ============================================================================
namespace Http {

struct UrlParts {
    std::string scheme;
    std::string host;
    int         port;
    std::string path;
};

UrlParts parseUrl(const std::string& url) {
    UrlParts p;
    auto schemeEnd = url.find("://");
    if (schemeEnd == std::string::npos) {
        p.scheme = "http";
        schemeEnd = 0;
    } else {
        p.scheme = url.substr(0, schemeEnd);
        schemeEnd += 3;
    }
    auto pathStart = url.find('/', schemeEnd);
    std::string hostPart = (pathStart == std::string::npos)
        ? url.substr(schemeEnd) : url.substr(schemeEnd, pathStart - schemeEnd);
    p.path = (pathStart == std::string::npos) ? "/" : url.substr(pathStart);

    auto colonPos = hostPart.find(':');
    if (colonPos != std::string::npos) {
        p.host = hostPart.substr(0, colonPos);
        p.port = std::stoi(hostPart.substr(colonPos + 1));
    } else {
        p.host = hostPart;
        p.port = (p.scheme == "https") ? 443 : 80;
    }
    return p;
}
struct HttpResponse {
    int status = 0;
    std::string body;
    json parsed;
    bool ok() const { return status == 200; }
};

template<typename Client>
HttpResponse doRequest(Client& cli, const std::string& path, int timeout_ms, int retries,
                       const std::string* body = nullptr, const std::string* contentType = nullptr) {
    cli.set_connection_timeout(timeout_ms / 1000);
    cli.set_read_timeout(timeout_ms / 1000);
    cli.set_write_timeout(timeout_ms / 1000);
    cli.set_keep_alive(false);
    cli.set_address_family(AF_INET);

    HttpResponse resp;
    for (int i = 0; i <= retries; ++i) {
        auto res = body && contentType ? cli.Post(path.c_str(), *body, contentType->c_str()) : cli.Get(path.c_str());

        if (res) {
            resp.status = res->status;
            resp.body = res->body;

            if (res->status == 200) {
                try { resp.parsed = json::parse(res->body); return resp; }
                catch (...) {
                    LOG_WARN("JSON parse fail, retrying");
                    resp.status = 0;
                }
            } else if (res->status == 429) {
                try { resp.parsed = json::parse(res->body); } catch (...) {}
                return resp;
            }

            LOG_WARN("HTTP " + std::to_string(res->status) + " retry=" + std::to_string(i));
        }

        if (i < retries) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500 * (i + 1)));
        }
    }
    return resp;
}

HttpResponse get(const std::string& url, int timeout_ms = 8000, int retries = 2) {
    auto p = parseUrl(url);
    if (p.scheme == "https") {
        httplib::SSLClient cli(p.host, p.port);        cli.enable_server_certificate_verification(true);
        return doRequest(cli, p.path, timeout_ms, retries);
    } else {
        httplib::Client cli(p.host, p.port);
        return doRequest(cli, p.path, timeout_ms, retries);
    }
}

HttpResponse post(const std::string& url, const json& body,
                  int timeout_ms = 8000, int retries = 2) {
    auto p = parseUrl(url);
    std::string dump = body.dump();
    static const std::string jsonType = "application/json";
    if (p.scheme == "https") {
        httplib::SSLClient cli(p.host, p.port);
        cli.enable_server_certificate_verification(true);
        return doRequest(cli, p.path, timeout_ms, retries, &dump, &jsonType);
    } else {
        httplib::Client cli(p.host, p.port);
        return doRequest(cli, p.path, timeout_ms, retries, &dump, &jsonType);
    }
}

bool getJson(const std::string& url, json& out, int timeout_ms = 8000, int retries = 2) {
    auto r = get(url, timeout_ms, retries);
    if (r.ok()) { out = r.parsed; return true; }
    return false;
}

} // namespace Http

// ============================================================================
//  DATABASE
// ============================================================================
class DB {
    sqlite3* db_ = nullptr;
    mutable std::mutex mtx_;

    static constexpr const char* KEY_MESSAGES   = "stats_messages";
    static constexpr const char* KEY_TX_OK      = "stats_tx_ok";
    static constexpr const char* KEY_ERRORS     = "stats_errors";
    static constexpr const char* KEY_RPC_ERR    = "stats_rpc_err";
    static constexpr const char* KEY_MARKET_ERR = "stats_market_err";
    static constexpr const char* KEY_TG_ERR     = "stats_tg_err";
    static constexpr const char* KEY_LAST_TX    = "last_tx";
    static constexpr const char* KEY_LAST_RPC_OK= "last_rpc_ok";
    static constexpr const char* KEY_LAST_MKT_OK= "last_mkt_ok";
    static constexpr const char* KEY_INSERTS_SINCE_CLEANUP = "inserts_since_cleanup";

public:    ~DB() { if (db_) sqlite3_close(db_); }

    bool open(const std::string& path) {
        if (sqlite3_open(path.c_str(), &db_) != SQLITE_OK) {
            LOG_ERR(std::string("SQLite open fail: ") + sqlite3_errmsg(db_));
            return false;
        }
        execUnlocked("PRAGMA journal_mode=WAL;");
        execUnlocked("PRAGMA synchronous=NORMAL;");
        execUnlocked("PRAGMA busy_timeout=5000;");
        execUnlocked("PRAGMA auto_vacuum=INCREMENTAL;");

        execUnlocked("CREATE TABLE IF NOT EXISTS processed_tx("
             "  tx_hash TEXT PRIMARY KEY,"
             "  ts INTEGER NOT NULL,"
             "  status INTEGER NOT NULL DEFAULT 0,"
             "  retry_count INTEGER NOT NULL DEFAULT 0"
             ");");
        execUnlocked("CREATE INDEX IF NOT EXISTS idx_tx_ts ON processed_tx(ts);");
        execUnlocked("CREATE INDEX IF NOT EXISTS idx_tx_status ON processed_tx(status);");
        execUnlocked("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);");
        
        migrateAddStatusColumnIfMissing();
        migrateAddRetryCountColumnIfMissing();
        checkAutoVacuumMode();

        return true;
    }

    bool ping() const {
        std::lock_guard<std::mutex> lk(mtx_);
        sqlite3_stmt* s;
        if (sqlite3_prepare_v2(db_, "SELECT 1;", -1, &s, nullptr) != SQLITE_OK) return false;
        bool ok = sqlite3_step(s) == SQLITE_ROW;
        sqlite3_finalize(s);
        return ok;
    }

    bool exists(const std::string& tx) const {
        std::lock_guard<std::mutex> lk(mtx_);
        sqlite3_stmt* s;
        if (sqlite3_prepare_v2(db_, "SELECT 1 FROM processed_tx WHERE tx_hash=?", -1, &s, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_text(s, 1, tx.c_str(), -1, SQLITE_STATIC);
        bool r = sqlite3_step(s) == SQLITE_ROW;
        sqlite3_finalize(s);
        return r;
    }

    bool insert(const std::string& tx) {
        std::lock_guard<std::mutex> lk(mtx_);        sqlite3_stmt* s;
        if (sqlite3_prepare_v2(db_, "INSERT OR IGNORE INTO processed_tx(tx_hash,ts) VALUES(?,?)", -1, &s, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_text(s, 1, tx.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(s, 2, std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        bool ok = sqlite3_step(s) == SQLITE_DONE;
        sqlite3_finalize(s);
        return ok;
    }

    // Atomic insert to prevent duplicate processing
    bool tryClaim(const std::string& tx) {
        std::lock_guard<std::mutex> lk(mtx_);
        sqlite3_stmt* s;
        if (sqlite3_prepare_v2(db_, "INSERT OR IGNORE INTO processed_tx(tx_hash,ts,status) VALUES(?,?,0)", -1, &s, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_text(s, 1, tx.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(s, 2, std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        sqlite3_step(s);
        sqlite3_finalize(s);
        return sqlite3_changes(db_) > 0;
    }

    void markDone(const std::string& tx) {
        std::lock_guard<std::mutex> lk(mtx_);
        sqlite3_stmt* s;
        if (sqlite3_prepare_v2(db_, "UPDATE processed_tx SET status=1 WHERE tx_hash=?", -1, &s, nullptr) != SQLITE_OK) return;
        sqlite3_bind_text(s, 1, tx.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(s);
        sqlite3_finalize(s);
    }

    std::vector<std::string> reclaimAfterRestart() {
        std::lock_guard<std::mutex> lk(mtx_);
        std::vector<std::string> out;
        sqlite3_stmt* s;
        if (sqlite3_prepare_v2(db_, "SELECT tx_hash FROM processed_tx WHERE status=0", -1, &s, nullptr) != SQLITE_OK) return out;
        while (sqlite3_step(s) == SQLITE_ROW) {
            const char* v = (const char*)sqlite3_column_text(s, 0);
            if (v) out.push_back(v);
        }
        sqlite3_finalize(s);
        return out;
    }

    std::vector<std::string> tryRequeueStale(int64_t maxAgeSeconds, int maxAttempts) {
        std::lock_guard<std::mutex> lk(mtx_);
        std::vector<std::string> toRequeue;
        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();        int64_t cutoff = now - maxAgeSeconds;

        std::vector<std::pair<std::string, int>> candidates;
        sqlite3_stmt* s;
        if (sqlite3_prepare_v2(db_, "SELECT tx_hash, retry_count FROM processed_tx WHERE status=0 AND ts<=?", -1, &s, nullptr) != SQLITE_OK) return toRequeue;
        sqlite3_bind_int64(s, 1, cutoff);
        while (sqlite3_step(s) == SQLITE_ROW) {
            const char* v = (const char*)sqlite3_column_text(s, 0);
            int retryCount = sqlite3_column_int(s, 1);
            if (v) candidates.emplace_back(v, retryCount);
        }
        sqlite3_finalize(s);

        for (const auto& [txHash, retryCount] : candidates) {
            if (retryCount >= maxAttempts) {
                sqlite3_stmt* upd;
                if (sqlite3_prepare_v2(db_, "UPDATE processed_tx SET status=2 WHERE tx_hash=?", -1, &upd, nullptr) == SQLITE_OK) {
                    sqlite3_bind_text(upd, 1, txHash.c_str(), -1, SQLITE_STATIC);
                    sqlite3_step(upd);
                    sqlite3_finalize(upd);
                }
                LOG_ERR("Abandoning tx " + txHash + " after " + std::to_string(retryCount) + " attempts.");
            } else {
                sqlite3_stmt* upd;
                if (sqlite3_prepare_v2(db_, "UPDATE processed_tx SET ts=?, retry_count=retry_count+1 WHERE tx_hash=?", -1, &upd, nullptr) == SQLITE_OK) {
                    sqlite3_bind_int64(upd, 1, now);
                    sqlite3_bind_text(upd, 2, txHash.c_str(), -1, SQLITE_STATIC);
                    sqlite3_step(upd);
                    sqlite3_finalize(upd);
                }
                toRequeue.push_back(txHash);
            }
        }
        return toRequeue;
    }

    int getAbandonedCount() const {
        std::lock_guard<std::mutex> lk(mtx_);
        sqlite3_stmt* s;
        if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM processed_tx WHERE status=2", -1, &s, nullptr) != SQLITE_OK) return 0;
        int n = 0;
        if (sqlite3_step(s) == SQLITE_ROW) n = sqlite3_column_int(s, 0);
        sqlite3_finalize(s);
        return n;
    }

    void cleanup(int keep) {
        std::lock_guard<std::mutex> lk(mtx_);
        std::string sql = "DELETE FROM processed_tx WHERE status=1 AND rowid NOT IN ("
                          "  SELECT rowid FROM processed_tx WHERE status=1 ORDER BY ts DESC LIMIT " +                          std::to_string(keep) + ")";
        execUnlocked(sql);
        execUnlocked("PRAGMA incremental_vacuum;");
        execUnlocked("PRAGMA wal_checkpoint(PASSIVE);");
        setMetaUnlocked(KEY_INSERTS_SINCE_CLEANUP, "0");
        LOG_INFO("DB cleanup: kept last " + std::to_string(keep) + " done rows.");
    }

    bool noteInsertedAndShouldCleanup(int trigger) {
        std::lock_guard<std::mutex> lk(mtx_);
        std::string v = getMetaUnlocked(KEY_INSERTS_SINCE_CLEANUP);
        long count = v.empty() ? 0 : std::stol(v);
        ++count;
        setMetaUnlocked(KEY_INSERTS_SINCE_CLEANUP, std::to_string(count));
        return count >= trigger;
    }

    void saveOffset(long offset) { setMeta("offset", std::to_string(offset)); }
    long loadOffset() const { std::string v = getMeta("offset"); return v.empty() ? 0 : std::stol(v); }

    void incMessages()   { incMeta(KEY_MESSAGES); }
    void incTxOk()       { incMeta(KEY_TX_OK); }
    void incErrors()     { incMeta(KEY_ERRORS); }
    void incRpcErr()     { incMeta(KEY_RPC_ERR); }
    void incMarketErr()  { incMeta(KEY_MARKET_ERR); }
    void incTgErr()      { incMeta(KEY_TG_ERR); }

    uint64_t getMessages()   const { return getMetaU64(KEY_MESSAGES); }
    uint64_t getTxOk()       const { return getMetaU64(KEY_TX_OK); }
    uint64_t getErrors()     const { return getMetaU64(KEY_ERRORS); }
    uint64_t getRpcErr()     const { return getMetaU64(KEY_RPC_ERR); }
    uint64_t getMarketErr()  const { return getMetaU64(KEY_MARKET_ERR); }
    uint64_t getTgErr()      const { return getMetaU64(KEY_TG_ERR); }

    void setLastTx(const std::string& tx)   { setMeta(KEY_LAST_TX, tx); }
    void setLastRpcOk(int64_t ts)           { setMeta(KEY_LAST_RPC_OK, std::to_string(ts)); }
    void setLastMktOk(int64_t ts)           { setMeta(KEY_LAST_MKT_OK, std::to_string(ts)); }

    std::string getLastTx() const { return getMeta(KEY_LAST_TX); }
    int64_t getLastRpcOk() const { std::string v = getMeta(KEY_LAST_RPC_OK); return v.empty() ? 0 : std::stoll(v); }
    int64_t getLastMktOk() const { std::string v = getMeta(KEY_LAST_MKT_OK); return v.empty() ? 0 : std::stoll(v); }

    int getTotalProcessed() const {
        std::lock_guard<std::mutex> lk(mtx_);
        sqlite3_stmt* s;
        if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM processed_tx", -1, &s, nullptr) != SQLITE_OK) return 0;
        int n = 0;
        if (sqlite3_step(s) == SQLITE_ROW) n = sqlite3_column_int(s, 0);
        sqlite3_finalize(s);
        return n;    }

    int64_t getDbSizeBytes() const {
        std::error_code ec;
        auto size = fs::file_size(cfg::DB_PATH, ec);
        return ec ? 0 : size;
    }

    void maintenance() {
        std::lock_guard<std::mutex> lk(mtx_);
        execUnlocked("PRAGMA incremental_vacuum;");
        execUnlocked("PRAGMA wal_checkpoint(TRUNCATE);");
        LOG_INFO("DB maintenance completed");
    }

private:
    std::string getMetaUnlocked(const std::string& key) const {
        sqlite3_stmt* s;
        if (sqlite3_prepare_v2(db_, "SELECT value FROM meta WHERE key=?", -1, &s, nullptr) != SQLITE_OK) return "";
        sqlite3_bind_text(s, 1, key.c_str(), -1, SQLITE_STATIC);
        std::string result;
        if (sqlite3_step(s) == SQLITE_ROW) {
            const char* v = (const char*)sqlite3_column_text(s, 0);
            if (v) result = v;
        }
        sqlite3_finalize(s);
        return result;
    }

    void setMetaUnlocked(const std::string& key, const std::string& value) {
        sqlite3_stmt* s;
        if (sqlite3_prepare_v2(db_,
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", -1, &s, nullptr) != SQLITE_OK) return;
        sqlite3_bind_text(s, 1, key.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(s, 2, value.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(s);
        sqlite3_finalize(s);
    }

    void incMetaUnlocked(const std::string& key) {
        std::string sql = "INSERT INTO meta(key,value) VALUES(?, '1') "
                          "ON CONFLICT(key) DO UPDATE SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT);";
        sqlite3_stmt* s;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &s, nullptr) != SQLITE_OK) return;
        sqlite3_bind_text(s, 1, key.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(s);
        sqlite3_finalize(s);
    }
    std::string getMeta(const std::string& key) const {
        std::lock_guard<std::mutex> lk(mtx_);
        return getMetaUnlocked(key);
    }

    void setMeta(const std::string& key, const std::string& value) {
        std::lock_guard<std::mutex> lk(mtx_);
        setMetaUnlocked(key, value);
    }

    void incMeta(const std::string& key) {
        std::lock_guard<std::mutex> lk(mtx_);
        incMetaUnlocked(key);
    }

    uint64_t getMetaU64(const std::string& key) const {
        std::string v = getMeta(key);
        return v.empty() ? 0 : std::stoull(v);
    }

    void migrateAddStatusColumnIfMissing() {
        sqlite3_stmt* s;
        if (sqlite3_prepare_v2(db_, "PRAGMA table_info(processed_tx);", -1, &s, nullptr) != SQLITE_OK) return;
        bool hasStatus = false;
        while (sqlite3_step(s) == SQLITE_ROW) {
            const char* colName = (const char*)sqlite3_column_text(s, 1);
            if (colName && std::string(colName) == "status") { hasStatus = true; break; }
        }
        sqlite3_finalize(s);
        if (!hasStatus) {
            execUnlocked("ALTER TABLE processed_tx ADD COLUMN status INTEGER NOT NULL DEFAULT 1;");
        }
    }

    void migrateAddRetryCountColumnIfMissing() {
        sqlite3_stmt* s;
        if (sqlite3_prepare_v2(db_, "PRAGMA table_info(processed_tx);", -1, &s, nullptr) != SQLITE_OK) return;
        bool hasRetryCount = false;
        while (sqlite3_step(s) == SQLITE_ROW) {
            const char* colName = (const char*)sqlite3_column_text(s, 1);
            if (colName && std::string(colName) == "retry_count") { hasRetryCount = true; break; }
        }
        sqlite3_finalize(s);
        if (!hasRetryCount) {
            execUnlocked("ALTER TABLE processed_tx ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0;");
        }
    }

    void checkAutoVacuumMode() {
        sqlite3_stmt* s;        if (sqlite3_prepare_v2(db_, "PRAGMA auto_vacuum;", -1, &s, nullptr) != SQLITE_OK) return;
        int mode = -1;
        if (sqlite3_step(s) == SQLITE_ROW) mode = sqlite3_column_int(s, 0);
        sqlite3_finalize(s);
        if (mode != 2) {
            LOG_WARN("auto_vacuum is NOT incremental. Run manual VACUUM if needed.");
        }
    }

    void execUnlocked(const std::string& sql) {
        char* err = nullptr;
        sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err);
        if (err) { LOG_WARN(std::string("SQL: ") + err); sqlite3_free(err); }
    }
};

// ============================================================================
//  BOT STATS
// ============================================================================
struct BotStats {
    std::chrono::system_clock::time_point startTime;

    std::atomic<uint64_t> totalMessagesReceived{0};
    std::atomic<uint64_t> totalTxProcessed{0};
    std::atomic<uint64_t> totalErrors{0};
    std::atomic<uint64_t> rpcErrors{0};
    std::atomic<uint64_t> marketErrors{0};
    std::atomic<uint64_t> telegramErrors{0};

    std::atomic<int64_t> lastRpcOkTs{0};
    std::atomic<int64_t> lastMktOkTs{0};
    std::string lastTx;
    std::mutex lastTxMtx;

    void loadFromDb(const DB& db) {
        totalMessagesReceived.store(db.getMessages());
        totalTxProcessed.store(db.getTxOk());
        totalErrors.store(db.getErrors());
        rpcErrors.store(db.getRpcErr());
        marketErrors.store(db.getMarketErr());
        telegramErrors.store(db.getTgErr());
        lastRpcOkTs.store(db.getLastRpcOk());
        lastMktOkTs.store(db.getLastMktOk());
        lastTx = db.getLastTx();
    }

    void setLastTx(const std::string& tx) {
        std::lock_guard<std::mutex> lk(lastTxMtx);
        lastTx = tx;
    }    std::string getLastTx() {
        std::lock_guard<std::mutex> lk(lastTxMtx);
        return lastTx;
    }
};

// ============================================================================
//  BSC RPC
// ============================================================================
class BscRpc {
    size_t idx_ = 0;
    mutable std::mutex mtx_;
public:
    bool call(const std::string& method, const json& params, json& result) {
        std::lock_guard<std::mutex> lk(mtx_);
        for (size_t attempt = 0; attempt < cfg::BSC_RPC.size(); ++attempt) {
            const std::string& url = cfg::BSC_RPC[(idx_ + attempt) % cfg::BSC_RPC.size()];
            json req = {{"jsonrpc","2.0"},{"id",1},{"method",method},{"params",params}};
            auto resp = Http::post(url, req);
            if (resp.ok() && resp.parsed.contains("result") && !resp.parsed["result"].is_null()) {
                result = resp.parsed["result"];
                idx_ = (idx_ + attempt) % cfg::BSC_RPC.size();
                return true;
            }
            LOG_WARN("RPC fail: " + url + " method=" + method);
        }
        return false;
    }

    bool getTx(const std::string& hash, json& out) { return call("eth_getTransactionByHash", {hash}, out); }
    bool getReceipt(const std::string& hash, json& out) { return call("eth_getTransactionReceipt", {hash}, out); }

    std::string getCurrentRpc() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return cfg::BSC_RPC[idx_ % cfg::BSC_RPC.size()];
    }
};

// ============================================================================
//  TX CLASSIFIER
// ============================================================================
struct TxInfo {
    std::string type;
    std::string tokenAddr;
    std::string from;
    std::string to;
};

namespace classifier {
const std::string TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

inline unsigned char toLowerChar(unsigned char c) {
    return static_cast<unsigned char>(std::tolower(c));
}

std::string padAddr(const std::string& hex) {
    if (hex.size() < 40) return "";
    std::string tail = hex.substr(hex.size() - 40);
    std::transform(tail.begin(), tail.end(), tail.begin(), toLowerChar);
    return "0x" + tail;
}

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), toLowerChar);
    return s;
}

bool isStablecoin(const std::string& addr) {
    std::string a = toLower(addr);
    for (const auto& sc : cfg::STABLECOINS) {
        if (a == toLower(sc)) return true;
    }
    return false;
}

TxInfo classify(const json& tx, const json& receipt, const std::string& whaleAddr) {
    TxInfo info;
    info.from = toLower(tx.value("from", ""));
    info.to   = toLower(tx.value("to", ""));
    std::string whale = toLower(whaleAddr);

    json logs = receipt.value("logs", json::array());
    LOG_INFO("LOGS_COUNT=" + std::to_string(logs.size()));

    bool whaleSentStable = false, whaleGotStable = false;
    bool whaleSentToken = false, whaleGotToken = false;
    std::string tokenContract;

    for (const auto& log : logs) {
        LOG_INFO("LOG_ADDR=" + log.value("address",""));
        auto topics = log.value("topics", json::array());
        if (topics.size() < 3) continue;
        std::string topic0 = toLower(topics[0].get<std::string>());
        if (topic0 != TRANSFER_TOPIC) continue;

        std::string from = padAddr(topics[1].get<std::string>());
        std::string to   = padAddr(topics[2].get<std::string>());
        std::string contract = toLower(log.value("address", ""));
        bool isStable = isStablecoin(contract);
        bool fromWhale = (from == whale);
        bool toWhale = (to == whale);

        if (isStable) {
            if (fromWhale) whaleSentStable = true;
            if (toWhale)   whaleGotStable = true;
        } else {
            if (fromWhale) { whaleSentToken = true; if (tokenContract.empty()) tokenContract = contract; }
            if (toWhale)   { whaleGotToken = true;  if (tokenContract.empty()) tokenContract = contract; }
        }
    }

    LOG_INFO("DEBUG tokenContract=[" + tokenContract + "]");
    info.tokenAddr = tokenContract;

    if (whaleSentStable && whaleGotToken) info.type = "BUY";
    else if (whaleSentToken && whaleGotStable) info.type = "SELL";
    else if (whaleSentToken && !whaleGotToken && !whaleSentStable && !whaleGotStable) info.type = "SEND";
    else if (whaleGotToken && !whaleSentToken && !whaleSentStable && !whaleGotStable) info.type = "RECEIVE";
    else info.type = "UNKNOWN";

    return info;
}
} // namespace classifier

// ============================================================================
//  MESSAGE PARSER
// ============================================================================
struct ParsedMsg {
    std::string whaleName, txHash, contract, coin, amount, quantity, whaleAddr;
};

ParsedMsg parseMessage(const std::string& text) {
    ParsedMsg p;
    {
        std::istringstream iss(text);
        std::string line;
        while (std::getline(iss, line)) {
            size_t a = line.find_first_not_of(" \t\r\n");
            if (a == std::string::npos) continue;
            line = line.substr(a);
            if (!line.empty()) { p.whaleName = line; break; }
        }
    }

    static const std::regex TX_HASH_RE(R"((?:TX|Хеш|Hash)\s*[:：]\s*(0x[0-9a-fA-F]{64}))");
    static const std::regex CONTRACT_RE(R"((?:Контракт|Contract)\s*[:：]\s*(0x[0-9a-fA-F]{40}))");
    static const std::regex COIN_RE(R"(🪙\s*([A-Za-z0-9]+))");
    static const std::regex AMOUNT_RE(R"([💰\$]\s*\$?([0-9]+[.,]?[0-9]*[kKmMbB]?))");    static const std::regex QUANTITY_RE(R"(🔢\s*([0-9]+[.,]?[0-9]*[kKmMbB]?))");
    static const std::regex WHALE_ADDR_RE(R"(👤\s*(0x[0-9a-fA-F]{40}))");

    auto extractFirst = [&](const std::regex& re) -> std::string {
        std::smatch m;
        if (std::regex_search(text, m, re)) return m[1].str();
        return "";
    };

    p.txHash    = extractFirst(TX_HASH_RE);
    p.contract  = extractFirst(CONTRACT_RE);
    p.coin      = extractFirst(COIN_RE);
    p.amount    = extractFirst(AMOUNT_RE);
    p.quantity  = extractFirst(QUANTITY_RE);
    p.whaleAddr = extractFirst(WHALE_ADDR_RE);

    return p;
}

// ============================================================================
//  MARKET DATA
// ============================================================================
struct OhlcvCandle {
    int64_t timestamp;
    double open, high, low, close, volume;
};

struct MarketData {
    bool ok = false;
    std::string source;
    double priceUsd = 0, liquidityUsd = 0;
    std::string symbol, pairAddress;
    std::vector<OhlcvCandle> candles1m;
};

bool findOhlcvList(const json& j, json& out) {
    if (j.contains("ohlcv_list")) { out = j["ohlcv_list"]; return true; }
    if (j.is_object()) { for (auto it = j.begin(); it != j.end(); ++it) if (findOhlcvList(it.value(), out)) return true; }
    if (j.is_array()) { for (const auto& item : j) if (findOhlcvList(item, out)) return true; }
    return false;
}

class MarketAggregator {
public:
    MarketData fetch(const std::string& contract) {
        MarketData md;
        std::string c = classifier::toLower(contract);
        if (tryDexScreener(c, md)) return md;
        LOG_WARN("DexScreener fail, fallback to GeckoTerminal");
        if (tryGeckoTerminal(c, md)) return md;        LOG_WARN("GeckoTerminal fail, Market Data unavailable");
        return md;
    }

private:
    bool tryDexScreener(const std::string& contract, MarketData& md) {
        auto resp = Http::get(cfg::DEXSCREENER_BASE + "/latest/dex/tokens/" + contract);
        if (!resp.ok()) return false;
        auto pairs = resp.parsed.value("pairs", json::array());
        if (pairs.empty()) return false;

        json best; double bestLiq = -1;
        for (const auto& p : pairs) {
            if (p.value("chainId","") != "bsc") continue;
            double liq = p.value("liquidity", json::object()).value("usd", 0.0);
            if (liq > bestLiq) { bestLiq = liq; best = p; }
        }
        if (best.is_null()) return false;

        md.source = "DexScreener"; md.ok = true;
        try { md.priceUsd = std::stod(best.value("priceUsd", std::string("0"))); } catch(...) { md.priceUsd = 0; }
        md.liquidityUsd = bestLiq;
        md.symbol = best.value("baseToken", json::object()).value("symbol", "");
        md.pairAddress = best.value("pairAddress", "");

        if (!md.pairAddress.empty()) fetchOhlcvGecko(md.pairAddress, md.candles1m);
        return true;
    }

    bool tryGeckoTerminal(const std::string& contract, MarketData& md) {
        std::string url = cfg::GECKO_BASE + "/api/v2/networks/bsc/tokens/" + contract + "/pools?limit=1";
        auto resp = Http::get(url, 10000);
        if (!resp.ok()) return false;
        auto data = resp.parsed.value("data", json::array());
        if (data.empty()) return false;
        auto attr = data[0].value("attributes", json::object());

        md.source = "GeckoTerminal"; md.ok = true;
        try {
            md.priceUsd = std::stod(attr.value("token_price_usd", "0"));
            md.liquidityUsd = std::stod(attr.value("reserve_in_usd", "0"));
        } catch (...) { return false; }

        md.pairAddress = data[0].value("id", "");
        auto rel = resp.parsed.value("included", json::array());
        for (const auto& r : rel) {
            if (r.value("type","") == "token") {
                md.symbol = r.value("attributes", json::object()).value("symbol", "");
                break;
            }        }

        std::string addr = md.pairAddress;
        if (addr.rfind("bsc_", 0) == 0) addr = addr.substr(4);
        fetchOhlcvGecko(addr, md.candles1m);
        return true;
    }

    void fetchOhlcvGecko(const std::string& addr, std::vector<OhlcvCandle>& candles) {
        std::string url = cfg::GECKO_BASE + "/api/v2/networks/bsc/pools/" + addr +
                          "/ohlcv/minute?aggregate=1&limit=130&currency=usd";
        auto resp = Http::get(url, 10000);
        if (!resp.ok()) return;

        json ohlcvArr;
        if (!findOhlcvList(resp.parsed, ohlcvArr)) return;

        std::vector<OhlcvCandle> tmp;
        for (const auto& c : ohlcvArr) {
            if (!c.is_array() || c.size() < 6) continue;
            try {
                OhlcvCandle candle;
                candle.timestamp = c[0].get<int64_t>();
                candle.open = c[1].get<double>(); candle.high = c[2].get<double>();
                candle.low = c[3].get<double>(); candle.close = c[4].get<double>();
                candle.volume = c[5].get<double>();
                tmp.push_back(candle);
            } catch (...) {}
        }
        candles.assign(tmp.rbegin(), tmp.rend());
    }
};

// ============================================================================
//  INDICATORS
// ============================================================================
namespace ind {

double rsi(const std::vector<OhlcvCandle>& candles, int period) {
    if ((int)candles.size() < period + 1) return NAN;
    double gain = 0, loss = 0;
    for (int i = 1; i <= period; ++i) {
        double d = candles[i].close - candles[i-1].close;
        if (d >= 0) gain += d; else loss -= d;
    }
    double avgGain = gain / period, avgLoss = loss / period;
    for (size_t i = period + 1; i < candles.size(); ++i) {
        double d = candles[i].close - candles[i-1].close;
        avgGain = (avgGain * (period - 1) + (d > 0 ? d : 0)) / period;
        avgLoss = (avgLoss * (period - 1) + (d < 0 ? -d : 0)) / period;    }
    if (avgLoss == 0) return 100.0;
    return 100.0 - 100.0 / (1.0 + (avgGain / avgLoss));
}

std::vector<double> rsiSeriesAll(const std::vector<OhlcvCandle>& candles, int period) {
    std::vector<double> out;
    if ((int)candles.size() < period + 1) return out;

    double gain = 0, loss = 0;
    for (int i = 1; i <= period; ++i) {
        double d = candles[i].close - candles[i-1].close;
        if (d >= 0) gain += d; else loss -= d;
    }
    double avgGain = gain / period, avgLoss = loss / period;
    auto rsiFromAvgs = [](double ag, double al) -> double {
        if (al == 0) return 100.0;
        return 100.0 - 100.0 / (1.0 + (ag / al));
    };
    out.push_back(rsiFromAvgs(avgGain, avgLoss));

    for (size_t i = period + 1; i < candles.size(); ++i) {
        double d = candles[i].close - candles[i-1].close;
        avgGain = (avgGain * (period - 1) + (d > 0 ? d : 0)) / period;
        avgLoss = (avgLoss * (period - 1) + (d < 0 ? -d : 0)) / period;
        out.push_back(rsiFromAvgs(avgGain, avgLoss));
    }
    return out;
}

double stochRsi(const std::vector<OhlcvCandle>& candles, int rsiPeriod = 14, int stochPeriod = 14) {
    if ((int)candles.size() < rsiPeriod + stochPeriod) return NAN;
    std::vector<double> rsiSeries = rsiSeriesAll(candles, rsiPeriod);
    if ((int)rsiSeries.size() < stochPeriod) return NAN;
    double mn = *std::min_element(rsiSeries.end() - stochPeriod, rsiSeries.end());
    double mx = *std::max_element(rsiSeries.end() - stochPeriod, rsiSeries.end());
    if (mx == mn) return 50.0;
    return (rsiSeries.back() - mn) / (mx - mn);
}

// Delta of RSI/StochRSI between current candle and N candles ago
double delta(const std::vector<OhlcvCandle>& candles, int period, int n, bool isStoch = false) {
    if ((int)candles.size() < period + n) return NAN;
    
    std::vector<OhlcvCandle> oldCandles(candles.begin(), candles.end() - n);
    double oldVal = isStoch ? stochRsi(oldCandles, period) : rsi(oldCandles, period);
    double curVal = isStoch ? stochRsi(candles, period) : rsi(candles, period);
    
    if (std::isnan(oldVal) || std::isnan(curVal)) return NAN;
    return curVal - oldVal;}

double sumVolume(const std::vector<OhlcvCandle>& candles, int n) {
    if ((int)candles.size() < n) return 0;
    double sum = 0;
    for (int i = (int)candles.size() - n; i < (int)candles.size(); ++i) sum += candles[i].volume;
    return sum;
}

std::string rsiColor(double v) {
    if (std::isnan(v)) return "⚪";
    if (v < 20) return "🔴"; if (v < 30) return "🟠"; if (v < 70) return "🟡"; if (v < 80) return "🟢"; return "🔵";
}
std::string stochColor(double v) {
    if (std::isnan(v)) return "⚪";
    if (v < 0.10) return "🔴"; if (v < 0.20) return "🟠"; if (v < 0.80) return "🟡"; if (v < 0.90) return "🟢"; return "🔵";
}
std::string volColor(double pct) {
    if (pct < 50) return "🔴"; if (pct < 100) return "🟠"; if (pct < 150) return "🟡"; if (pct < 300) return "🟢"; return "🔵";
}
std::string liqColor(double usd) {
    if (usd < 20000) return "🔴"; if (usd < 50000) return "🟠"; if (usd < 150000) return "🟡"; if (usd < 500000) return "🟢"; return "🔵";
}

std::string fmtNum(double v) {
    std::ostringstream s;
    if (std::abs(v) >= 1e9) s << std::fixed << std::setprecision(2) << v/1e9 << "B";
    else if (std::abs(v) >= 1e6) s << std::fixed << std::setprecision(2) << v/1e6 << "M";
    else if (std::abs(v) >= 1e3) s << std::fixed << std::setprecision(1) << v/1e3 << "k";
    else s << std::fixed << std::setprecision(2) << v;
    return s.str();
}

} // namespace ind

// ============================================================================
//  TELEGRAM BOT
// ============================================================================
class TgBot {
    std::string token_, apiBase_;
    int64_t lastHealthCheckTs_ = 0;

public:
    TgBot(const std::string& token) : token_(token), apiBase_("https://api.telegram.org/bot" + token) {}

    json getUpdates(long offset) {
        json out;
        std::string url = apiBase_ + "/getUpdates?timeout=" + std::to_string(cfg::POLL_TIMEOUT_SEC)
                          + "&allowed_updates=[\"message\",\"channel_post\"]&offset=" + std::to_string(offset);
        Http::getJson(url, out, (cfg::POLL_TIMEOUT_SEC + 5) * 1000, 1);        return out;
    }

    bool sendMessage(int64_t chatId, const std::string& text) {
        json body = {{"chat_id", chatId}, {"text", text}, {"disable_web_page_preview", true}};
        for (int attempt = 0; attempt < 3; ++attempt) {
            auto resp = Http::post(apiBase_ + "/sendMessage", body);
            if (resp.status == 200) return true;
            if (resp.status == 429) {
                int retryAfter = 5;
                if (resp.parsed.contains("parameters")) retryAfter = resp.parsed["parameters"].value("retry_after", 5);
                LOG_WARN("Telegram rate limit 429, retry after " + std::to_string(retryAfter) + "s");
                std::this_thread::sleep_for(std::chrono::seconds(retryAfter));
                continue;
            }
            LOG_ERR("Telegram sendMessage failed: HTTP " + std::to_string(resp.status));
            return false;
        }
        return false;
    }

    void handleCommand(const std::string& cmd, int64_t chatId,
                       const BotStats& stats, const DB& db,
                       const BscRpc& rpc, long currentOffset) {
        if (cmd == "/stats") {
            sendStats(chatId, stats, db);
        } else if (cmd == "/health") {
            int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            int64_t elapsed = now - lastHealthCheckTs_;
            if (lastHealthCheckTs_ != 0 && elapsed < cfg::HEALTH_COMMAND_COOLDOWN_SEC) {
                sendMessage(chatId, "⏳ /health was just run " + std::to_string(elapsed) + "s ago.");
                return;
            }
            lastHealthCheckTs_ = now;
            sendHealth(chatId, db, rpc, currentOffset);
        }
    }

private:
    void sendStats(int64_t chatId, const BotStats& stats, const DB& db) {
        auto now = std::chrono::system_clock::now();
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - stats.startTime).count();
        int days = uptime / 86400, hours = (uptime % 86400) / 3600, mins = (uptime % 3600) / 60;

        std::ostringstream s;
        s << "📊 BOT STATS\n\n";
        s << "⏱ Uptime: " << days << "d " << hours << "h " << mins << "m\n";
        s << "📨 Messages received: " << stats.totalMessagesReceived.load() << "\n";
        s << "✅ TX processed: " << stats.totalTxProcessed.load() << "\n";        s << "❌ Total errors: " << stats.totalErrors.load() << "\n";
        s << "💾 Database:\n";
        s << "   ├─ Total TX in DB: " << db.getTotalProcessed() << "\n";
        int abandoned = db.getAbandonedCount();
        if (abandoned > 0) s << "   ├─ ⚠️ Abandoned TX: " << abandoned << "\n";
        int64_t dbSize = db.getDbSizeBytes();
        if (dbSize >= 1024 * 1024) s << "   └─ DB size: " << std::fixed << std::setprecision(2) << (dbSize / (1024.0 * 1024.0)) << " MB\n";
        else s << "   └─ DB size: " << (dbSize / 1024) << " KB\n";
        sendMessage(chatId, s.str());
    }

    void sendHealth(int64_t chatId, const DB& db, const BscRpc& rpc, long currentOffset) {
        std::ostringstream s;
        s << "🏥 HEALTH CHECK\n\n";
        bool dbOk = db.ping();
        s << (dbOk ? "✅ Database: OK\n" : "❌ Database: FAIL\n");

        bool rpcOk = false; std::string workingRpc;
        for (const auto& rpcUrl : cfg::BSC_RPC) {
            json req = {{"jsonrpc","2.0"},{"id",1},{"method","eth_blockNumber"},{"params",json::array()}};
            auto resp = Http::post(rpcUrl, req, cfg::HEALTH_TIMEOUT_MS, 0);
            if (resp.ok() && resp.parsed.contains("result")) { rpcOk = true; workingRpc = rpcUrl; break; }
        }
        s << (rpcOk ? "✅ BSC RPC: OK\n" : "❌ BSC RPC: FAIL\n");

        bool tgOk = false;
        auto tgResp = Http::get(apiBase_ + "/getMe", cfg::HEALTH_TIMEOUT_MS, 0);
        if (tgResp.ok() && tgResp.parsed.value("ok", false)) tgOk = true;
        s << (tgOk ? "✅ Telegram API: OK\n" : "❌ Telegram API: FAIL\n");

        bool dexOk = false, geckoOk = false;
        auto dexResp = Http::get(cfg::DEXSCREENER_BASE + "/latest/dex/tokens/0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c", cfg::HEALTH_TIMEOUT_MS, 0);
        if (dexResp.ok()) dexOk = true;
        s << (dexOk ? "✅ DexScreener: OK\n" : "⚠️ DexScreener: UNAVAILABLE\n");

        auto geckoResp = Http::get(cfg::GECKO_BASE + "/api/v2/networks/bsc/tokens/0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c/pools?limit=1", cfg::HEALTH_TIMEOUT_MS, 0);
        if (geckoResp.ok()) geckoOk = true;
        s << (geckoOk ? "✅ GeckoTerminal: OK\n" : "⚠️ GeckoTerminal: UNAVAILABLE\n");

        s << "\n🔧 DETAILS\n";
        s << "Current RPC: " << (workingRpc.empty() ? rpc.getCurrentRpc() : workingRpc) << "\n";

        std::string lastTx = db.getLastTx();
        if (lastTx.size() >= 16) s << "Last TX: " << lastTx.substr(0, 10) << "..." << lastTx.substr(lastTx.size() - 6) << "\n";
        else if (!lastTx.empty()) s << "Last TX: " << lastTx << "\n";
        else s << "Last TX: none\n";

        s << "Current offset: " << currentOffset << "\n";
        int64_t lastMktTs = db.getLastMktOk();
        if (lastMktTs > 0) {            auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            s << "Last market fetch: " << (now - lastMktTs) << " sec ago\n";
        } else s << "Last market fetch: never\n";

        s << "\n";
        s << (dbOk && rpcOk && tgOk ? "🟢 System: HEALTHY\n" : "🔴 System: DEGRADED\n");
        sendMessage(chatId, s.str());
    }
};

// ============================================================================
//  MAINTENANCE THREAD
// ============================================================================
class MaintenanceThread {
    std::thread thread_; std::mutex mtx_; std::condition_variable cv_; std::atomic<bool> stop_{false}; DB* db_;
public:
    explicit MaintenanceThread(DB* db) : db_(db) {}
    void start() {
        thread_ = std::thread([this]() {
            std::unique_lock<std::mutex> lk(mtx_);
            while (!stop_.load()) {
                cv_.wait_for(lk, std::chrono::hours(cfg::MAINTENANCE_INTERVAL_HOURS), [this]() { return stop_.load(); });
                if (stop_.load()) break;
                db_->maintenance();
            }
        });
    }
    void stop() { stop_.store(true); cv_.notify_all(); if (thread_.joinable()) thread_.join(); }
};

// ============================================================================
//  MESSAGE BUILDER (с дельтами 3/15/60)
// ============================================================================
std::string typeEmoji(const std::string& t) {
    if (t == "BUY") return "🟢 BUY"; if (t == "SELL") return "🔴 SELL";
    if (t == "SEND") return "📤 SEND"; if (t == "RECEIVE") return "📥 RECEIVE"; return "❓ UNKNOWN";
}

std::string buildReport(const ParsedMsg& p, const TxInfo& tx, const MarketData& md) {
    std::ostringstream s;
    s << "🔍 ANALYZER\n\n";
    s << "🐋 " << (p.whaleName.empty() ? "Unknown" : p.whaleName) << "\n\n";
    s << typeEmoji(tx.type) << "\n";
    s << "🪙 " << (!md.symbol.empty() ? md.symbol : (!p.coin.empty() ? p.coin :
        (tx.tokenAddr.size() > 10 ? tx.tokenAddr.substr(0, 10) + "..." : tx.tokenAddr))) << "\n";
    if (md.priceUsd > 0) s << "💰 $" << std::fixed << std::setprecision(4) << md.priceUsd << "\n";
    s << "\n";

    bool haveEnough = (int)md.candles1m.size() >= cfg::MIN_OHLCV_FOR_1H + cfg::RSI_PERIOD;
    bool haveBasic  = (int)md.candles1m.size() >= cfg::RSI_PERIOD + 1;
    double rsiNow = NAN, rsi1h = NAN, srsiNow = NAN, srsi1h = NAN, volNow = 0, vol1h = 0;

    if (haveBasic) {
        rsiNow = ind::rsi(md.candles1m, cfg::RSI_PERIOD);
        srsiNow = ind::stochRsi(md.candles1m);
        volNow = ind::sumVolume(md.candles1m, 60);
    }
    if (haveEnough) {
        std::vector<OhlcvCandle> oldCandles(md.candles1m.begin(), md.candles1m.end() - 60);
        rsi1h = ind::rsi(oldCandles, cfg::RSI_PERIOD);
        srsi1h = ind::stochRsi(oldCandles);
        vol1h = ind::sumVolume(oldCandles, 60);
    }

    // RSI с дельтами 3/15/60
    s << "📈 RSI\n";
    if (std::isnan(rsiNow)) {
        s << "⚠️ RSI недоступен\n";
    } else {
        s << ind::rsiColor(rsiNow) << " " << std::fixed << std::setprecision(1) << rsiNow << "\n";
        
        // Δ3
        double rsiDelta3 = ind::delta(md.candles1m, cfg::RSI_PERIOD, 3);
        if (!std::isnan(rsiDelta3)) {
            std::string arrow = rsiDelta3 >= 0 ? "⬆️" : "⬇️";
            s << "Δ3: " << (rsiDelta3 >= 0 ? "+" : "") << std::fixed << std::setprecision(1) << rsiDelta3 << " " << arrow << "\n";
        }
        
        // Δ15
        double rsiDelta15 = ind::delta(md.candles1m, cfg::RSI_PERIOD, 15);
        if (!std::isnan(rsiDelta15)) {
            std::string arrow = rsiDelta15 >= 0 ? "⬆️" : "⬇️";
            s << "Δ15: " << (rsiDelta15 >= 0 ? "+" : "") << std::fixed << std::setprecision(1) << rsiDelta15 << " " << arrow << "\n";
        }
        
        // Δ60
        if (!std::isnan(rsi1h)) {
            double diff = rsiNow - rsi1h;
            std::string arrow = diff >= 0 ? "⬆️" : "⬇️";
            s << "Δ60: " << (diff >= 0 ? "+" : "") << std::fixed << std::setprecision(1) << diff << " " << arrow << "\n";
        }
    }
    s << "\n";

    // Stoch RSI с дельтами 3/15/60
    s << "📊 Stoch RSI\n";
    if (std::isnan(srsiNow)) {
        s << "⚠️ Stoch RSI недоступен\n";
    } else {        s << ind::stochColor(srsiNow) << " " << std::fixed << std::setprecision(2) << srsiNow << "\n";
        
        // Δ3
        double srsiDelta3 = ind::delta(md.candles1m, cfg::RSI_PERIOD, 3, true);
        if (!std::isnan(srsiDelta3)) {
            std::string arrow = srsiDelta3 >= 0 ? "⬆️" : "⬇️";
            s << "Δ3: " << (srsiDelta3 >= 0 ? "+" : "") << std::fixed << std::setprecision(2) << srsiDelta3 << " " << arrow << "\n";
        }
        
        // Δ15
        double srsiDelta15 = ind::delta(md.candles1m, cfg::RSI_PERIOD, 15, true);
        if (!std::isnan(srsiDelta15)) {
            std::string arrow = srsiDelta15 >= 0 ? "⬆️" : "⬇️";
            s << "Δ15: " << (srsiDelta15 >= 0 ? "+" : "") << std::fixed << std::setprecision(2) << srsiDelta15 << " " << arrow << "\n";
        }
        
        // Δ60
        if (!std::isnan(srsi1h)) {
            double diff = srsiNow - srsi1h;
            std::string arrow = diff >= 0 ? "⬆️" : "⬇️";
            s << "Δ60: " << (diff >= 0 ? "+" : "") << std::fixed << std::setprecision(2) << diff << " " << arrow << "\n";
        }
    }
    s << "\n";

    // Volume с дельтами 3/15/60
    s << "📦 Объём\n";
    if (!md.ok || volNow == 0) {
        s << "⚠️ Объём недоступен\n";
    } else {
        s << ind::volColor(100) << " " << ind::fmtNum(volNow) << " (60m)\n";
        
        // Δ3: объем за последние 3 минуты vs предыдущие 3 минуты
        if ((int)md.candles1m.size() >= 6) {
            double vol3recent = ind::sumVolume(md.candles1m, 3);
            std::vector<OhlcvCandle> prev3(md.candles1m.begin(), md.candles1m.end() - 3);
            double vol3prev = ind::sumVolume(prev3, 3);
            if (vol3prev > 0) {
                double pct = ((vol3recent - vol3prev) / vol3prev) * 100.0;
                std::string arrow = pct >= 0 ? "⬆️" : "⬇️";
                s << "Δ3: " << (pct >= 0 ? "+" : "") << std::fixed << std::setprecision(0) << pct << "% " << arrow << "\n";
            }
        }
        
        // Δ15: объем за последние 15 минут vs предыдущие 15 минут
        if ((int)md.candles1m.size() >= 30) {
            double vol15recent = ind::sumVolume(md.candles1m, 15);
            std::vector<OhlcvCandle> prev15(md.candles1m.begin(), md.candles1m.end() - 15);
            double vol15prev = ind::sumVolume(prev15, 15);
            if (vol15prev > 0) {                double pct = ((vol15recent - vol15prev) / vol15prev) * 100.0;
                std::string arrow = pct >= 0 ? "⬆️" : "⬇️";
                s << "Δ15: " << (pct >= 0 ? "+" : "") << std::fixed << std::setprecision(0) << pct << "% " << arrow << "\n";
            }
        }
        
        // Δ60: объем за последние 60 минут vs предыдущие 60 минут
        if (haveEnough && vol1h > 0) {
            double pct = ((volNow - vol1h) / vol1h) * 100.0;
            std::string arrow = pct >= 0 ? "⬆️" : "⬇️";
            s << "Δ60: " << (pct >= 0 ? "+" : "") << std::fixed << std::setprecision(0) << pct << "% " << arrow << "\n";
        }
    }
    s << "\n";

    // Ликвидность (без дельт, только абсолютное значение)
    s << "💧 Ликвидность\n";
    if (!md.ok) {
        s << "⚠️ Ликвидность недоступна\n";
    } else {
        s << ind::liqColor(md.liquidityUsd) << " $" << ind::fmtNum(md.liquidityUsd) << "\n";
    }

    return s.str();
}

// ============================================================================
//  GRACEFUL SHUTDOWN
// ============================================================================
static std::atomic<bool> g_running{true};
void onSignal(int) { LOG_INFO("Signal received, shutting down..."); g_running = false; }

// ============================================================================
//  TASK QUEUE & WORKERS
// ============================================================================
struct WhaleTask { ParsedMsg parsed; std::string txLower; };

class TaskQueue {
    std::deque<WhaleTask> q_;
    mutable std::mutex mtx_;
    std::condition_variable cv_, notFullCv_;
    bool shuttingDown_ = false;
    size_t maxSize_;

public:
    explicit TaskQueue(size_t maxSize) : maxSize_(maxSize) {}

    bool push(WhaleTask task) {
        std::unique_lock<std::mutex> lk(mtx_);
        notFullCv_.wait(lk, [this]() { return q_.size() < maxSize_ || shuttingDown_; });        if (shuttingDown_) return false;
        q_.push_back(std::move(task));
        cv_.notify_one();
        return true;
    }

    bool tryPushFor(WhaleTask task, std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lk(mtx_);
        bool gotSlot = notFullCv_.wait_for(lk, timeout, [this]() { return q_.size() < maxSize_ || shuttingDown_; });
        if (!gotSlot || shuttingDown_) return false;
        q_.push_back(std::move(task));
        cv_.notify_one();
        return true;
    }

    bool pop(WhaleTask& out) {
        std::unique_lock<std::mutex> lk(mtx_);
        cv_.wait(lk, [this]() { return !q_.empty() || shuttingDown_; });
        if (q_.empty()) return false;
        out = std::move(q_.front());
        q_.pop_front();
        notFullCv_.notify_one();
        return true;
    }

    size_t size() const { std::lock_guard<std::mutex> lk(mtx_); return q_.size(); }
    void shutdown() { std::lock_guard<std::mutex> lk(mtx_); shuttingDown_ = true; cv_.notify_all(); notFullCv_.notify_all(); }
};

class WorkerHeartbeats {
    std::vector<std::atomic<int64_t>> lastBeat_;
public:
    explicit WorkerHeartbeats(int n) : lastBeat_(n) {
        int64_t now = nowSec(); for (auto& b : lastBeat_) b.store(now);
    }
    void beat(int workerId) { lastBeat_[workerId].store(nowSec()); }
    int64_t lastBeat(int workerId) const { return lastBeat_[workerId].load(); }
    int count() const { return (int)lastBeat_.size(); }
    static int64_t nowSec() { return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count(); }
};

class WorkerPool {
    std::vector<std::thread> threads_;
    TaskQueue& queue_; DB& db_; TgBot& bot_; BscRpc& rpc_; MarketAggregator& market_; BotStats& stats_; WorkerHeartbeats& heartbeats_;

public:
    WorkerPool(TaskQueue& queue, DB& db, TgBot& bot, BscRpc& rpc, MarketAggregator& market, BotStats& stats, WorkerHeartbeats& heartbeats)
        : queue_(queue), db_(db), bot_(bot), rpc_(rpc), market_(market), stats_(stats), heartbeats_(heartbeats) {}

    void start(int numWorkers) { for (int i = 0; i < numWorkers; ++i) threads_.emplace_back([this, i]() { run(i); }); }    void startReplacementWorker(int workerId) { threads_.emplace_back([this, workerId]() { run(workerId); }); }
    void joinAll() { for (auto& t : threads_) if (t.joinable()) t.join(); }

private:
    void run(int workerId) {
        WhaleTask task; heartbeats_.beat(workerId);
        while (queue_.pop(task)) {
            try { process(task, workerId); } catch (const std::exception& e) { LOG_ERR("worker exception: " + std::string(e.what())); }
            heartbeats_.beat(workerId);
        }
    }

    void process(const WhaleTask& task, int workerId) {
        const ParsedMsg& p = task.parsed; const std::string& txLower = task.txLower;
        LOG_INFO("Processing TX: " + txLower);

        json txData, receipt;
        bool haveTx = rpc_.getTx(txLower, txData);
        bool haveRc = rpc_.getReceipt(txLower, receipt);
        heartbeats_.beat(workerId);

        TxInfo tx;
        if (haveTx && haveRc) {
            std::string whaleAddr = p.whaleAddr.empty() ? txData.value("from", "") : p.whaleAddr;
            tx = classifier::classify(txData, receipt, whaleAddr);
            if (tx.type != "UNKNOWN") { stats_.totalTxProcessed++; db_.incTxOk(); }
            stats_.lastRpcOkTs.store(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
            db_.setLastRpcOk(stats_.lastRpcOkTs.load());
        } else {
            tx.type = "UNKNOWN"; stats_.rpcErrors++; stats_.totalErrors++; db_.incRpcErr(); db_.incErrors();
        }

        std::string contract = p.contract.empty() ? tx.tokenAddr : p.contract;
        MarketData md;
        if (!contract.empty()) {
            md = market_.fetch(contract);
            if (md.ok) {
                stats_.lastMktOkTs.store(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
                db_.setLastMktOk(stats_.lastMktOkTs.load());
            } else { stats_.marketErrors++; stats_.totalErrors++; db_.incMarketErr(); db_.incErrors(); }
        }
        heartbeats_.beat(workerId);

        std::string report = buildReport(p, tx, md);
        bool published = bot_.sendMessage(cfg::OUTPUT_CHANNEL, report);
        if (!published) { stats_.telegramErrors++; stats_.totalErrors++; db_.incTgErr(); db_.incErrors(); }
        heartbeats_.beat(workerId);

        stats_.setLastTx(txLower); db_.setLastTx(txLower);
        if (published) { db_.markDone(txLower); }

        if (db_.noteInsertedAndShouldCleanup(cfg::CLEANUP_TRIGGER)) db_.cleanup(cfg::KEEP_LAST_TX);
    }
};

// ============================================================================
//  BACKGROUND THREADS
// ============================================================================
class StaleTaskReclaimer {
    std::thread thread_; std::mutex mtx_; std::condition_variable cv_; std::atomic<bool> stop_{false}; DB* db_; TaskQueue* queue_;
public:
    StaleTaskReclaimer(DB* db, TaskQueue* queue) : db_(db), queue_(queue) {}
    void start() {
        thread_ = std::thread([this]() {
            std::unique_lock<std::mutex> lk(mtx_);
            while (!stop_.load()) {
                cv_.wait_for(lk, std::chrono::seconds(cfg::STALE_TASK_CHECK_INTERVAL_SEC), [this]() { return stop_.load(); });
                if (stop_.load()) break;
                auto stale = db_->tryRequeueStale(cfg::STALE_TASK_TTL_SECONDS, cfg::MAX_RECLAIM_ATTEMPTS);
                for (const auto& txLower : stale) {
                    WhaleTask task; task.txLower = txLower;
                    queue_->tryPushFor(std::move(task), std::chrono::milliseconds(cfg::STALE_RECLAIMER_PUSH_TIMEOUT_MS));
                }
            }
        });
    }
    void stop() { stop_.store(true); cv_.notify_all(); if (thread_.joinable()) thread_.join(); }
};

class Watchdog {
    std::thread thread_; std::mutex mtx_; std::condition_variable cv_; std::atomic<bool> stop_{false};
    WorkerHeartbeats& heartbeats_; WorkerPool& pool_;
    std::vector<int64_t> lastReactedTo_; std::vector<int> replacementCount_;

public:
    Watchdog(WorkerHeartbeats& heartbeats, WorkerPool& pool)
        : heartbeats_(heartbeats), pool_(pool), lastReactedTo_(heartbeats.count(), -1), replacementCount_(heartbeats.count(), 0) {}

    void start() {
        thread_ = std::thread([this]() {
            std::unique_lock<std::mutex> lk(mtx_);
            while (!stop_.load()) {
                cv_.wait_for(lk, std::chrono::seconds(cfg::WORKER_HEARTBEAT_CHECK_INTERVAL_SEC), [this]() { return stop_.load(); });
                if (stop_.load()) break;
                int64_t now = WorkerHeartbeats::nowSec();
                for (int i = 0; i < heartbeats_.count(); ++i) {
                    int64_t beat = heartbeats_.lastBeat(i);
                    if ((now - beat) > cfg::WORKER_HANG_TIMEOUT_SEC && lastReactedTo_[i] != beat) {
                        lastReactedTo_[i] = beat;                        if (replacementCount_[i] >= cfg::MAX_WORKER_REPLACEMENTS_PER_SLOT) continue;
                        replacementCount_[i]++;
                        pool_.startReplacementWorker(i);
                    }
                }
            }
        });
    }
    void stop() { stop_.store(true); cv_.notify_all(); if (thread_.joinable()) thread_.join(); }
};

// ============================================================================
//  MAIN
// ============================================================================
int main() {
    std::signal(SIGINT, onSignal); std::signal(SIGTERM, onSignal);
    std::error_code ec; fs::create_directories("logs", ec);
    LOG_INFO("=== Analyzer Bot v1.1 FINAL ===");

    DB db;
    if (!db.open(cfg::DB_PATH)) { LOG_ERR("Cannot open DB"); return 1; }

    TgBot bot(cfg::getBotToken());
    BscRpc rpc; MarketAggregator market;

    BotStats stats;
    stats.startTime = std::chrono::system_clock::now();
    stats.loadFromDb(db);

    long offset = db.loadOffset();
    if (offset == 0) {
        json j;
        if (Http::getJson("https://api.telegram.org/bot" + cfg::getBotToken() + "/getUpdates?limit=1&offset=-1", j)) {
            auto res = j.value("result", json::array());
            if (!res.empty()) offset = res.back().value("update_id", 0LL) + 1;
        }
    }

    MaintenanceThread maint(&db); maint.start();

    TaskQueue queue(cfg::MAX_QUEUE_SIZE);
    WorkerHeartbeats heartbeats(cfg::NUM_WORKER_THREADS);
    WorkerPool workers(queue, db, bot, rpc, market, stats, heartbeats);
    workers.start(cfg::NUM_WORKER_THREADS);

    Watchdog watchdog(heartbeats, workers); watchdog.start();
    StaleTaskReclaimer staleReclaimer(&db, &queue); staleReclaimer.start();

    for (const auto& txLower : db.reclaimAfterRestart()) {
        WhaleTask task; task.txLower = txLower;        queue.push(std::move(task));
    }

    while (g_running) {
        json resp;
        try { resp = bot.getUpdates(offset); } catch (const std::exception& e) { std::this_thread::sleep_for(std::chrono::seconds(2)); continue; }
        if (!resp.contains("result") || !resp["result"].is_array()) { std::this_thread::sleep_for(std::chrono::seconds(1)); continue; }

        auto updates = resp["result"];
        for (const auto& upd : updates) {
            long uid = upd.value("update_id", 0LL);
            if (uid >= offset) offset = uid + 1;

            if (upd.contains("message")) {
                auto msg = upd["message"];
                std::string text = msg.value("text", "");
                int64_t fromId = msg.value("from", json::object()).value("id", 0LL);
                int64_t chatId = msg.value("chat", json::object()).value("id", 0LL);
                if ((text == "/stats" || text == "/health") && fromId == cfg::ADMIN_ID) {
                    bot.handleCommand(text, chatId, stats, db, rpc, offset); continue;
                }
            }

            if (!upd.contains("channel_post")) continue;
            auto post = upd["channel_post"];
            if (post.value("chat", json::object()).value("id", 0LL) != cfg::SOURCE_CHANNEL) continue;

            std::string text = post.value("text", "");
            if (text.empty()) continue;

            stats.totalMessagesReceived++; db.incMessages();
            ParsedMsg p = parseMessage(text);
            if (p.txHash.empty()) continue;
            std::string txLower = classifier::toLower(p.txHash);

            if (!db.tryClaim(txLower)) continue;

            WhaleTask task; task.parsed = p; task.txLower = txLower;

            auto pushStart = std::chrono::steady_clock::now();
            bool pushed = queue.push(std::move(task));
            auto pushWaitMs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - pushStart).count();
            if (pushWaitMs > cfg::QUEUE_BLOCKED_WARN_MS) {
                LOG_WARN("Poller blocked " + std::to_string(pushWaitMs) + "ms pushing to queue.");
            }
        }
        if (!updates.empty()) db.saveOffset(offset);
    }

    watchdog.stop(); staleReclaimer.stop();    queue.shutdown(); workers.joinAll();
    maint.stop();
    LOG_INFO("=== Shutdown complete ===");
    return 0;
}
