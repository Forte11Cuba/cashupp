#include "cashu/core/models.hpp"
#include <stdexcept>
#include <sstream>
#include <iomanip>

using namespace std;
using namespace boost::multiprecision;

namespace cashu::core::models {

//=============================================================================
// Utility Functions Implementation
//=============================================================================

string unit_to_string(Unit unit) {
    switch (unit) {
        case Unit::sat: return "sat";
        case Unit::msat: return "msat";
        case Unit::usd: return "usd";
        case Unit::eur: return "eur";
        case Unit::btc: return "btc";
        case Unit::auth: return "auth";
        default:
            throw invalid_argument("Unknown unit: " + to_string(static_cast<int>(unit)));
    }
}

Unit string_to_unit(const string& unit_str) {
    if (unit_str == "sat") return Unit::sat;
    if (unit_str == "msat") return Unit::msat;
    if (unit_str == "usd") return Unit::usd;
    if (unit_str == "eur") return Unit::eur;
    if (unit_str == "btc") return Unit::btc;
    if (unit_str == "auth") return Unit::auth;
    throw invalid_argument("Unknown unit string: " + unit_str);
}

string method_to_string(Method method) {
    switch (method) {
        case Method::bolt11: return "bolt11";
        default:
            throw invalid_argument("Unknown method: " + to_string(static_cast<int>(method)));
    }
}

Method string_to_method(const string& method_str) {
    if (method_str == "bolt11") return Method::bolt11;
    throw invalid_argument("Unknown method string: " + method_str);
}

string proof_spent_state_to_string(ProofSpentState state) {
    switch (state) {
        case ProofSpentState::unspent: return "UNSPENT";
        case ProofSpentState::spent: return "SPENT";
        case ProofSpentState::pending: return "PENDING";
        default:
            throw invalid_argument("Unknown proof spent state: " + to_string(static_cast<int>(state)));
    }
}

ProofSpentState string_to_proof_spent_state(const string& state_str) {
    if (state_str == "UNSPENT") return ProofSpentState::unspent;
    if (state_str == "SPENT") return ProofSpentState::spent;
    if (state_str == "PENDING") return ProofSpentState::pending;
    throw invalid_argument("Unknown proof spent state string: " + state_str);
}

string mint_quote_state_to_string(MintQuoteState state) {
    switch (state) {
        case MintQuoteState::unpaid: return "UNPAID";
        case MintQuoteState::paid: return "PAID";
        case MintQuoteState::pending: return "PENDING";
        case MintQuoteState::issued: return "ISSUED";
        default:
            throw invalid_argument("Unknown mint quote state: " + to_string(static_cast<int>(state)));
    }
}

MintQuoteState string_to_mint_quote_state(const string& state_str) {
    if (state_str == "UNPAID") return MintQuoteState::unpaid;
    if (state_str == "PAID") return MintQuoteState::paid;
    if (state_str == "PENDING") return MintQuoteState::pending;
    if (state_str == "ISSUED") return MintQuoteState::issued;
    throw invalid_argument("Unknown mint quote state string: " + state_str);
}

string melt_quote_state_to_string(MeltQuoteState state) {
    switch (state) {
        case MeltQuoteState::unpaid: return "UNPAID";
        case MeltQuoteState::pending: return "PENDING";
        case MeltQuoteState::paid: return "PAID";
        default:
            throw invalid_argument("Unknown melt quote state: " + to_string(static_cast<int>(state)));
    }
}

MeltQuoteState string_to_melt_quote_state(const string& state_str) {
    if (state_str == "UNPAID") return MeltQuoteState::unpaid;
    if (state_str == "PENDING") return MeltQuoteState::pending;
    if (state_str == "PAID") return MeltQuoteState::paid;
    throw invalid_argument("Unknown melt quote state string: " + state_str);
}

int64_t timestamp_to_unix(const timestamp_t& tp) {
    return chrono::duration_cast<chrono::seconds>(tp.time_since_epoch()).count();
}

timestamp_t unix_to_timestamp(int64_t unix_time) {
    return timestamp_t(chrono::seconds(unix_time));
}

timestamp_t now() {
    return chrono::system_clock::now();
}

//=============================================================================
// JSON Serialization Implementations
//=============================================================================

// DBVersion
json DBVersion::to_json() const {
    return json{
        {"db", db},
        {"version", version}
    };
}

DBVersion DBVersion::from_json(const json& j) {
    DBVersion dbv;
    dbv.db = j.at("db").get<string>();
    dbv.version = j.at("version").get<int>();
    return dbv;
}

// MintKeyset
json MintKeyset::to_json() const {
    json j = {
        {"id", id},
        {"valid_from", timestamp_to_unix(valid_from)},
        {"valid_to", timestamp_to_unix(valid_to)},
        {"first_seen", timestamp_to_unix(first_seen)},
        {"active", active},
        {"unit", unit},
        {"amounts", amounts},
        {"balance", balance.str()},
        {"fees_paid", fees_paid.str()}
    };
    
    if (derivation_path) j["derivation_path"] = *derivation_path;
    if (seed) j["seed"] = *seed;
    if (encrypted_seed) j["encrypted_seed"] = *encrypted_seed;
    if (seed_encryption_method) j["seed_encryption_method"] = *seed_encryption_method;
    if (version) j["version"] = *version;
    if (input_fee_ppk) j["input_fee_ppk"] = *input_fee_ppk;
    
    return j;
}

MintKeyset MintKeyset::from_json(const json& j) {
    MintKeyset ks;
    ks.id = j.at("id").get<string>();
    ks.valid_from = unix_to_timestamp(j.at("valid_from").get<int64_t>());
    ks.valid_to = unix_to_timestamp(j.at("valid_to").get<int64_t>());
    ks.first_seen = unix_to_timestamp(j.at("first_seen").get<int64_t>());
    ks.active = j.at("active").get<bool>();
    ks.unit = j.at("unit").get<string>();
    ks.amounts = j.at("amounts").get<string>();
    ks.balance = cpp_int(j.at("balance").get<string>());
    ks.fees_paid = cpp_int(j.at("fees_paid").get<string>());
    
    if (j.contains("derivation_path") && !j["derivation_path"].is_null())
        ks.derivation_path = j["derivation_path"].get<string>();
    if (j.contains("seed") && !j["seed"].is_null())
        ks.seed = j["seed"].get<string>();
    if (j.contains("encrypted_seed") && !j["encrypted_seed"].is_null())
        ks.encrypted_seed = j["encrypted_seed"].get<string>();
    if (j.contains("seed_encryption_method") && !j["seed_encryption_method"].is_null())
        ks.seed_encryption_method = j["seed_encryption_method"].get<string>();
    if (j.contains("version") && !j["version"].is_null())
        ks.version = j["version"].get<string>();
    if (j.contains("input_fee_ppk") && !j["input_fee_ppk"].is_null())
        ks.input_fee_ppk = j["input_fee_ppk"].get<int>();
    
    return ks;
}

// MintPubkey
json MintPubkey::to_json() const {
    return json{
        {"id", id},
        {"amount", amount.str()},
        {"pubkey", pubkey}
    };
}

MintPubkey MintPubkey::from_json(const json& j) {
    MintPubkey mp;
    mp.id = j.at("id").get<string>();
    mp.amount = cpp_int(j.at("amount").get<string>());
    mp.pubkey = j.at("pubkey").get<string>();
    return mp;
}

// Promise
json Promise::to_json() const {
    json j = {
        {"amount", amount.str()},
        {"b_", b_},
        {"c_", c_}
    };
    
    if (id) j["id"] = *id;
    if (dleq_e) j["dleq_e"] = *dleq_e;
    if (dleq_s) j["dleq_s"] = *dleq_s;
    if (created) j["created"] = timestamp_to_unix(*created);
    if (mint_quote) j["mint_quote"] = *mint_quote;
    if (swap_id) j["swap_id"] = *swap_id;
    
    return j;
}

Promise Promise::from_json(const json& j) {
    Promise p;
    p.amount = cpp_int(j.at("amount").get<string>());
    p.b_ = j.at("b_").get<string>();
    p.c_ = j.at("c_").get<string>();
    
    if (j.contains("id") && !j["id"].is_null())
        p.id = j["id"].get<string>();
    if (j.contains("dleq_e") && !j["dleq_e"].is_null())
        p.dleq_e = j["dleq_e"].get<string>();
    if (j.contains("dleq_s") && !j["dleq_s"].is_null())
        p.dleq_s = j["dleq_s"].get<string>();
    if (j.contains("created") && !j["created"].is_null())
        p.created = unix_to_timestamp(j["created"].get<int64_t>());
    if (j.contains("mint_quote") && !j["mint_quote"].is_null())
        p.mint_quote = j["mint_quote"].get<string>();
    if (j.contains("swap_id") && !j["swap_id"].is_null())
        p.swap_id = j["swap_id"].get<string>();
    
    return p;
}

// ProofUsed
json ProofUsed::to_json() const {
    json j = {
        {"amount", amount.str()},
        {"c", c},
        {"secret", secret}
    };
    
    if (id) j["id"] = *id;
    if (y) j["y"] = *y;
    if (witness) j["witness"] = *witness;
    if (created) j["created"] = timestamp_to_unix(*created);
    if (melt_quote) j["melt_quote"] = *melt_quote;
    
    return j;
}

ProofUsed ProofUsed::from_json(const json& j) {
    ProofUsed pu;
    pu.amount = cpp_int(j.at("amount").get<string>());
    pu.c = j.at("c").get<string>();
    pu.secret = j.at("secret").get<string>();
    
    if (j.contains("id") && !j["id"].is_null())
        pu.id = j["id"].get<string>();
    if (j.contains("y") && !j["y"].is_null())
        pu.y = j["y"].get<string>();
    if (j.contains("witness") && !j["witness"].is_null())
        pu.witness = j["witness"].get<string>();
    if (j.contains("created") && !j["created"].is_null())
        pu.created = unix_to_timestamp(j["created"].get<int64_t>());
    if (j.contains("melt_quote") && !j["melt_quote"].is_null())
        pu.melt_quote = j["melt_quote"].get<string>();
    
    return pu;
}

// ProofPending
json ProofPending::to_json() const {
    json j = {
        {"amount", amount.str()},
        {"c", c},
        {"secret", secret},
        {"created", timestamp_to_unix(created)}
    };
    
    if (id) j["id"] = *id;
    if (y) j["y"] = *y;
    if (witness) j["witness"] = *witness;
    if (melt_quote) j["melt_quote"] = *melt_quote;
    
    return j;
}

ProofPending ProofPending::from_json(const json& j) {
    ProofPending pp;
    pp.amount = cpp_int(j.at("amount").get<string>());
    pp.c = j.at("c").get<string>();
    pp.secret = j.at("secret").get<string>();
    pp.created = unix_to_timestamp(j.at("created").get<int64_t>());
    
    if (j.contains("id") && !j["id"].is_null())
        pp.id = j["id"].get<string>();
    if (j.contains("y") && !j["y"].is_null())
        pp.y = j["y"].get<string>();
    if (j.contains("witness") && !j["witness"].is_null())
        pp.witness = j["witness"].get<string>();
    if (j.contains("melt_quote") && !j["melt_quote"].is_null())
        pp.melt_quote = j["melt_quote"].get<string>();
    
    return pp;
}

// MintQuote
json MintQuote::to_json() const {
    json j = {
        {"quote", quote},
        {"method", method},
        {"request", request},
        {"checking_id", checking_id},
        {"unit", unit},
        {"amount", amount.str()},
        {"paid", paid},
        {"issued", issued}
    };
    
    if (created_time) j["created_time"] = timestamp_to_unix(*created_time);
    if (paid_time) j["paid_time"] = timestamp_to_unix(*paid_time);
    if (state) j["state"] = *state;
    if (pubkey) j["pubkey"] = *pubkey;
    
    return j;
}

MintQuote MintQuote::from_json(const json& j) {
    MintQuote mq;
    mq.quote = j.at("quote").get<string>();
    mq.method = j.at("method").get<string>();
    mq.request = j.at("request").get<string>();
    mq.checking_id = j.at("checking_id").get<string>();
    mq.unit = j.at("unit").get<string>();
    mq.amount = cpp_int(j.at("amount").get<string>());
    mq.paid = j.at("paid").get<bool>();
    mq.issued = j.at("issued").get<bool>();
    
    if (j.contains("created_time") && !j["created_time"].is_null())
        mq.created_time = unix_to_timestamp(j["created_time"].get<int64_t>());
    if (j.contains("paid_time") && !j["paid_time"].is_null())
        mq.paid_time = unix_to_timestamp(j["paid_time"].get<int64_t>());
    if (j.contains("state") && !j["state"].is_null())
        mq.state = j["state"].get<string>();
    if (j.contains("pubkey") && !j["pubkey"].is_null())
        mq.pubkey = j["pubkey"].get<string>();
    
    return mq;
}

// MeltQuote
json MeltQuote::to_json() const {
    json j = {
        {"quote", quote},
        {"method", method},
        {"request", request},
        {"checking_id", checking_id},
        {"unit", unit},
        {"amount", amount.str()},
        {"paid", paid}
    };
    
    if (fee_reserve) j["fee_reserve"] = fee_reserve->str();
    if (created_time) j["created_time"] = timestamp_to_unix(*created_time);
    if (paid_time) j["paid_time"] = timestamp_to_unix(*paid_time);
    if (fee_paid) j["fee_paid"] = fee_paid->str();
    if (proof) j["proof"] = *proof;
    if (state) j["state"] = *state;
    if (payment_preimage) j["payment_preimage"] = *payment_preimage;
    if (change) j["change"] = *change;
    if (expiry) j["expiry"] = timestamp_to_unix(*expiry);
    if (outputs) j["outputs"] = *outputs;
    
    return j;
}

MeltQuote MeltQuote::from_json(const json& j) {
    MeltQuote mq;
    mq.quote = j.at("quote").get<string>();
    mq.method = j.at("method").get<string>();
    mq.request = j.at("request").get<string>();
    mq.checking_id = j.at("checking_id").get<string>();
    mq.unit = j.at("unit").get<string>();
    mq.amount = cpp_int(j.at("amount").get<string>());
    mq.paid = j.at("paid").get<bool>();
    
    if (j.contains("fee_reserve") && !j["fee_reserve"].is_null())
        mq.fee_reserve = cpp_int(j["fee_reserve"].get<string>());
    if (j.contains("created_time") && !j["created_time"].is_null())
        mq.created_time = unix_to_timestamp(j["created_time"].get<int64_t>());
    if (j.contains("paid_time") && !j["paid_time"].is_null())
        mq.paid_time = unix_to_timestamp(j["paid_time"].get<int64_t>());
    if (j.contains("fee_paid") && !j["fee_paid"].is_null())
        mq.fee_paid = cpp_int(j["fee_paid"].get<string>());
    if (j.contains("proof") && !j["proof"].is_null())
        mq.proof = j["proof"].get<string>();
    if (j.contains("state") && !j["state"].is_null())
        mq.state = j["state"].get<string>();
    if (j.contains("payment_preimage") && !j["payment_preimage"].is_null())
        mq.payment_preimage = j["payment_preimage"].get<string>();
    if (j.contains("change") && !j["change"].is_null())
        mq.change = j["change"].get<string>();
    if (j.contains("expiry") && !j["expiry"].is_null())
        mq.expiry = unix_to_timestamp(j["expiry"].get<int64_t>());
    if (j.contains("outputs") && !j["outputs"].is_null())
        mq.outputs = j["outputs"].get<string>();
    
    return mq;
}

// BalanceLog
json BalanceLog::to_json() const {
    return json{
        {"unit", unit},
        {"keyset_balance", keyset_balance},
        {"keyset_fees_paid", keyset_fees_paid},
        {"backend_balance", backend_balance},
        {"time", timestamp_to_unix(time)}
    };
}

BalanceLog BalanceLog::from_json(const json& j) {
    BalanceLog bl;
    bl.unit = j.at("unit").get<string>();
    bl.keyset_balance = j.at("keyset_balance").get<int>();
    bl.keyset_fees_paid = j.at("keyset_fees_paid").get<int>();
    bl.backend_balance = j.at("backend_balance").get<int>();
    bl.time = unix_to_timestamp(j.at("time").get<int64_t>());
    return bl;
}

// WalletProof
json WalletProof::to_json() const {
    json j = {
        {"amount", amount.str()},
        {"C", C},
        {"secret", secret}
    };
    
    if (id) j["id"] = *id;
    if (reserved) j["reserved"] = *reserved;
    if (send_id) j["send_id"] = *send_id;
    if (time_created) j["time_created"] = timestamp_to_unix(*time_created);
    if (time_reserved) j["time_reserved"] = timestamp_to_unix(*time_reserved);
    if (derivation_path) j["derivation_path"] = *derivation_path;
    if (dleq) j["dleq"] = *dleq;
    if (mint_id) j["mint_id"] = *mint_id;
    if (melt_id) j["melt_id"] = *melt_id;
    
    return j;
}

WalletProof WalletProof::from_json(const json& j) {
    WalletProof wp;
    wp.amount = cpp_int(j.at("amount").get<string>());
    wp.C = j.at("C").get<string>();
    wp.secret = j.at("secret").get<string>();
    
    if (j.contains("id") && !j["id"].is_null())
        wp.id = j["id"].get<string>();
    if (j.contains("reserved") && !j["reserved"].is_null())
        wp.reserved = j["reserved"].get<bool>();
    if (j.contains("send_id") && !j["send_id"].is_null())
        wp.send_id = j["send_id"].get<string>();
    if (j.contains("time_created") && !j["time_created"].is_null())
        wp.time_created = unix_to_timestamp(j["time_created"].get<int64_t>());
    if (j.contains("time_reserved") && !j["time_reserved"].is_null())
        wp.time_reserved = unix_to_timestamp(j["time_reserved"].get<int64_t>());
    if (j.contains("derivation_path") && !j["derivation_path"].is_null())
        wp.derivation_path = j["derivation_path"].get<string>();
    if (j.contains("dleq") && !j["dleq"].is_null())
        wp.dleq = j["dleq"].get<string>();
    if (j.contains("mint_id") && !j["mint_id"].is_null())
        wp.mint_id = j["mint_id"].get<string>();
    if (j.contains("melt_id") && !j["melt_id"].is_null())
        wp.melt_id = j["melt_id"].get<string>();
    
    return wp;
}

// Balance
json Balance::to_json() const {
    return json{
        {"keyset", keyset},
        {"balance", balance.str()}
    };
}

Balance Balance::from_json(const json& j) {
    Balance b;
    b.keyset = j.at("keyset").get<string>();
    b.balance = cpp_int(j.at("balance").get<string>());
    return b;
}

// Implement remaining serialization methods for other structs...
// (Similar patterns for WalletProofUsed, WalletKeyset, Invoice, Seed, etc.)
// For brevity, I'll implement a few more key ones:

// Invoice
json Invoice::to_json() const {
    json j = {
        {"amount", amount},
        {"bolt11", bolt11},
        {"paid", paid},
        {"time_created", timestamp_to_unix(time_created)},
        {"time_paid", timestamp_to_unix(time_paid)}
    };
    
    if (id) j["id"] = *id;
    if (payment_hash) j["payment_hash"] = *payment_hash;
    if (preimage) j["preimage"] = *preimage;
    if (out) j["out"] = *out;
    
    return j;
}

Invoice Invoice::from_json(const json& j) {
    Invoice inv;
    inv.amount = j.at("amount").get<int>();
    inv.bolt11 = j.at("bolt11").get<string>();
    inv.paid = j.at("paid").get<bool>();
    inv.time_created = unix_to_timestamp(j.at("time_created").get<int64_t>());
    inv.time_paid = unix_to_timestamp(j.at("time_paid").get<int64_t>());
    
    if (j.contains("id") && !j["id"].is_null())
        inv.id = j["id"].get<string>();
    if (j.contains("payment_hash") && !j["payment_hash"].is_null())
        inv.payment_hash = j["payment_hash"].get<string>();
    if (j.contains("preimage") && !j["preimage"].is_null())
        inv.preimage = j["preimage"].get<string>();
    if (j.contains("out") && !j["out"].is_null())
        inv.out = j["out"].get<bool>();
    
    return inv;
}

// User
json User::to_json() const {
    json j = {
        {"id", id}
    };
    
    if (last_access) j["last_access"] = timestamp_to_unix(*last_access);
    
    return j;
}

User User::from_json(const json& j) {
    User u;
    u.id = j.at("id").get<string>();
    
    if (j.contains("last_access") && !j["last_access"].is_null())
        u.last_access = unix_to_timestamp(j["last_access"].get<int64_t>());
    
    return u;
}

} // namespace cashu::core::models