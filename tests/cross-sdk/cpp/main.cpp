#include <aun/aun_client.h>
#include <aun/aun_config.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <filesystem>
#include <future>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

using aun::AUNClient;
using aun::AUNConfig;
using aun::ConnectOptions;
using aun::ConnectionState;
using aun::Result;
using aun::StateToString;
using aun::Subscription;
using json = aun::json;

std::string env_string(const char* name, const std::string& fallback = "") {
    const char* value = std::getenv(name);
    if (value && *value) return value;
    return fallback;
}

bool env_bool(const char* name, bool fallback = false) {
    std::string value = env_string(name);
    std::transform(value.begin(), value.end(), value.begin(), ::tolower);
    if (value == "1" || value == "true" || value == "yes" || value == "on") return true;
    if (value == "0" || value == "false" || value == "no" || value == "off") return false;
    return fallback;
}

std::string random_hex() {
    static std::atomic<unsigned long long> counter{0};
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    std::ostringstream oss;
    oss << std::hex << now << counter.fetch_add(1);
    return oss.str();
}

std::string string_value(const json& value, const std::string& fallback = "") {
    if (value.is_string()) return value.get<std::string>();
    if (value.is_number_integer()) return std::to_string(value.get<long long>());
    if (value.is_number_unsigned()) return std::to_string(value.get<unsigned long long>());
    if (value.is_number_float()) return std::to_string(value.get<double>());
    if (value.is_boolean()) return value.get<bool>() ? "true" : "false";
    return fallback;
}

std::string get_string(const json& object, const std::string& key, const std::string& fallback = "") {
    if (!object.is_object() || !object.contains(key)) return fallback;
    return string_value(object.at(key), fallback);
}

long long get_int(const json& object, const std::string& key, long long fallback = 0) {
    if (!object.is_object() || !object.contains(key)) return fallback;
    const auto& value = object.at(key);
    if (value.is_number_integer()) return value.get<long long>();
    if (value.is_number_unsigned()) return static_cast<long long>(value.get<unsigned long long>());
    if (value.is_number_float()) return static_cast<long long>(value.get<double>());
    if (value.is_string()) {
        try { return std::stoll(value.get<std::string>()); } catch (...) { return fallback; }
    }
    return fallback;
}

bool get_bool(const json& object, const std::string& key, bool fallback = false) {
    if (!object.is_object() || !object.contains(key)) return fallback;
    const auto& value = object.at(key);
    if (value.is_boolean()) return value.get<bool>();
    if (value.is_string()) {
        std::string s = value.get<std::string>();
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        if (s == "1" || s == "true" || s == "yes" || s == "on") return true;
        if (s == "0" || s == "false" || s == "no" || s == "off") return false;
    }
    return fallback;
}

json safe_json(const json& value) {
    return value;
}

std::string first_non_empty(std::initializer_list<std::string> values) {
    for (const auto& value : values) {
        if (!value.empty()) return value;
    }
    return "";
}

std::string result_code(const Result& result) {
    return std::to_string(static_cast<int>(result.code()));
}

template <typename T>
bool wait_future(std::future<T>& future, int timeout_seconds) {
    return future.wait_for(std::chrono::seconds(timeout_seconds)) == std::future_status::ready;
}

struct RpcOutcome {
    Result result;
    json response;
};

Result create_aid_sync(const std::shared_ptr<AUNClient>& client, const std::string& aid, int timeout_seconds = 30) {
    auto promise = std::make_shared<std::promise<Result>>();
    auto delivered = std::make_shared<std::atomic<bool>>(false);
    auto future = promise->get_future();
    client->auth.createAid(aid, [promise, delivered](Result result, json) {
        if (!delivered->exchange(true)) promise->set_value(std::move(result));
    });
    if (!wait_future(future, timeout_seconds)) {
        delivered->store(true);
        return Result::Error("createAid timeout", aun::ErrorCode::Timeout);
    }
    return future.get();
}

Result connect_sync(const std::shared_ptr<AUNClient>& client,
                    const std::string& aid,
                    const std::string& slot_id,
                    int timeout_seconds = 30) {
    ConnectOptions options;
    options.slot_id = slot_id;
    options.auto_reconnect = env_bool("AUN_TEST_AUTO_RECONNECT", false);
    options.heartbeat_interval = 60;
    options.timeouts.connect = 5000;
    options.timeouts.call = 35000;
    options.timeouts.http = 30000;

    auto promise = std::make_shared<std::promise<Result>>();
    auto delivered = std::make_shared<std::atomic<bool>>(false);
    auto future = promise->get_future();
    client->ConnectWithIdentity(aid, options, [promise, delivered](Result result) {
        if (!delivered->exchange(true)) promise->set_value(std::move(result));
    });
    if (!wait_future(future, timeout_seconds)) {
        delivered->store(true);
        return Result::Error("ConnectWithIdentity timeout", aun::ErrorCode::Timeout);
    }
    return future.get();
}

RpcOutcome call_sync(const std::shared_ptr<AUNClient>& client,
                     const std::string& method,
                     const json& params,
                     int timeout_seconds = 35) {
    auto promise = std::make_shared<std::promise<RpcOutcome>>();
    auto delivered = std::make_shared<std::atomic<bool>>(false);
    auto future = promise->get_future();
    client->Call(method, params, [promise, delivered](Result result, json response) {
        if (!delivered->exchange(true)) {
            promise->set_value(RpcOutcome{std::move(result), std::move(response)});
        }
    }, timeout_seconds * 1000);
    if (!wait_future(future, timeout_seconds + 2)) {
        delivered->store(true);
        return {Result::Error("RPC timeout: " + method, aun::ErrorCode::Timeout), json::object()};
    }
    return future.get();
}

std::string sha256_placeholder(const json& value) {
    std::hash<std::string> h;
    std::ostringstream oss;
    oss << std::hex << h(value.dump());
    return oss.str();
}

class CrossSdkCppAgent {
public:
    CrossSdkCppAgent()
        : language_("cpp"),
          sdk_version_("unknown"),
          aid_(env_string("AUN_TEST_AID", "cross-cpp.agentid.pub")),
          issuer_(env_string("AUN_TEST_ISSUER", "agentid.pub")),
          gateway_url_(env_string("AUN_GATEWAY_URL")),
          slot_id_(env_string("AUN_TEST_SLOT_ID", "cross-sdk-cpp")),
          aun_path_(env_string("AUN_TEST_AUN_PATH", env_string("AUN_DATA_ROOT", "/data/aun"))),
          debug_(env_bool("AUN_TEST_DEBUG", false)) {
        if (issuer_.empty()) issuer_ = "agentid.pub";
        if (slot_id_.empty()) slot_id_ = "cross-sdk-cpp-" + random_hex().substr(0, 8);
        std::filesystem::create_directories(aun_path_);
        AUNConfig config;
        config.storage_path = aun_path_;
        config.verify_ssl = false;
        config.group_e2ee = true;
        config.require_forward_secrecy = false;
        config.debug = debug_;
        config.log_level = debug_ ? aun::LogLevel::Debug : aun::LogLevel::Info;
        if (!gateway_url_.empty()) config.ap_base_url = gateway_url_;
        client_ = AUNClient::Create(config);
        if (!client_) {
            startup_error_ = "AUNClient::Create returned null";
        }
    }

    void Start() {
        if (!startup_error_.empty()) return;
        subscriptions_.push_back(client_->Subscribe("message.received", [this](const json& msg) {
            store_inbox_item(normalize_message(msg, true, ""));
        }));
        subscriptions_.push_back(client_->Subscribe("message.undecryptable", [this](const json& msg) {
            store_inbox_item(normalize_message(msg, false, "undecryptable"));
        }));
        subscriptions_.push_back(client_->Subscribe("group.message_created", [this](const json& msg) {
            store_group_inbox_item(normalize_group_message(msg, true, ""));
        }));
        subscriptions_.push_back(client_->Subscribe("group.message_undecryptable", [this](const json& msg) {
            store_group_inbox_item(normalize_group_message(msg, false, "undecryptable"));
        }));

        auto create_result = create_aid_sync(client_, aid_);
        if (!create_result.ok() && client_->ExportIdentity(aid_).empty()) {
            startup_error_ = "createAid failed and no local identity exists: " + create_result.ToString();
            return;
        }
        auto connect_result = connect_sync(client_, aid_, slot_id_);
        if (!connect_result.ok()) {
            startup_error_ = "connect failed: " + connect_result.ToString();
            return;
        }
        std::lock_guard<std::mutex> lock(mu_);
        ready_ = true;
    }

    void Close() {
        if (client_) client_->Close();
    }

    json Handle(const std::string& method, const std::string& path, const json& body, int& status) {
        status = 200;
        const std::string route = path_only(path);
        try {
            if (method == "GET" && route == "/health") return health(status);
            if (method == "POST" && route == "/reset") return reset(body);
            if (method == "GET" && route == "/identity") return identity();
            if (method == "POST" && route == "/send") return send(body, status);
            if (method == "POST" && route == "/ack") return ack(body, status);
            if (method == "POST" && route == "/pull") return pull(body, status);
            if (method == "GET" && route == "/inbox") return inbox(path);
            if (method == "POST" && route == "/group/create") return group_create(body, status);
            if (method == "GET" && route == "/group/ready") return group_ready(path, status);
            if (method == "POST" && route == "/group/send") return group_send(body, status);
            if (method == "POST" && route == "/group/pull") return group_pull(body, status);
            if (method == "POST" && route == "/group/ack") return group_ack(body, status);
            if (method == "GET" && route == "/group/inbox") return group_inbox(path);
            if (method == "GET" && route.rfind("/traces/", 0) == 0) return trace(route.substr(std::string("/traces/").size()));
            if (method == "GET" && route == "/logs") return json{{"log_files", json::array()}, {"tail", json::array()}};
            status = 404;
            return json{{"ok", false}, {"error_code", "not_found"}, {"error_message", route}};
        } catch (const std::exception& exc) {
            status = 500;
            return json{{"ok", false}, {"error_code", "exception"}, {"error_message", exc.what()}};
        }
    }

private:
    json health(int& status) {
        std::lock_guard<std::mutex> lock(mu_);
        if (!startup_error_.empty()) status = 503;
        const auto state = client_ ? StateToString(client_->GetState()) : "closed";
        return json{
            {"ok", startup_error_.empty()},
            {"agent_ready", ready_ && state == "connected"},
            {"state", state},
            {"aid", aid_},
            {"language", language_},
            {"sdk_version", sdk_version_},
            {"gateway_url", gateway_url_},
            {"startup_error", startup_error_},
        };
    }

    json identity() {
        return json{
            {"aid", aid_},
            {"device_id", ""},
            {"slot_id", slot_id_},
            {"issuer", issuer_},
            {"public_key_fingerprint", ""},
        };
    }

    json reset(const json& body) {
        const std::string trace_id = get_string(body, "trace_id");
        std::lock_guard<std::mutex> lock(mu_);
        if (trace_id.empty()) {
            inbox_.clear();
            group_inbox_.clear();
            traces_.clear();
            send_results_.clear();
        } else {
            erase_trace(inbox_, trace_id);
            erase_trace(group_inbox_, trace_id);
            traces_.erase(trace_id);
            send_results_.erase(trace_id);
        }
        return json{{"ok", true}};
    }

    json send(const json& body, int& status) {
        const std::string trace_id = first_non_empty({get_string(body, "trace_id"), random_hex()});
        const std::string message_id = first_non_empty({get_string(body, "message_id"), trace_id + "-" + random_hex().substr(0, 8)});
        const std::string target = get_string(body, "to");
        const std::string text = get_string(body, "text");
        const bool e2ee = get_bool(body, "e2ee", true);
        if (target.empty()) {
            status = 400;
            return json{{"ok", false}, {"error_code", "bad_request"}, {"error_message", "to is required"}};
        }
        json payload = {
            {"type", "text"},
            {"text", text},
            {"trace_id", trace_id},
            {"case_id", first_non_empty({get_string(body, "case_id"), trace_id})},
        };
        auto outcome = call_sync(client_, "message.send", {
            {"to", target},
            {"payload", payload},
            {"encrypt", e2ee},
            {"message_id", message_id},
        }, timeout_seconds(body));
        if (!outcome.result.ok()) {
            status = 500;
            json out = error_response(trace_id, message_id, e2ee, outcome.result);
            record_trace(trace_id, json{{"stage", "send_error"}, {"target", target}, {"message_id", message_id}, {"error", out}});
            return out;
        }
        json out = {
            {"ok", true},
            {"trace_id", trace_id},
            {"message_id", message_id},
            {"seq", get_int(outcome.response, "seq", get_int(outcome.response, "message_seq"))},
            {"encrypted", e2ee},
            {"result", safe_json(outcome.response)},
        };
        {
            std::lock_guard<std::mutex> lock(mu_);
            send_results_[trace_id] = out;
        }
        record_trace(trace_id, json{{"stage", "send"}, {"target", target}, {"message_id", message_id}, {"result", out}});
        return out;
    }

    json ack(const json& body, int& status) {
        const long long seq = get_int(body, "seq", get_int(body, "up_to_seq"));
        json params = json::object();
        if (seq > 0) params["seq"] = seq;
        auto outcome = call_sync(client_, "message.ack", params);
        if (!outcome.result.ok()) {
            status = 500;
            return json{{"ok", false}, {"seq", seq}, {"error_code", result_code(outcome.result)}, {"error_message", outcome.result.message()}};
        }
        return json{{"ok", true}, {"seq", seq}, {"result", outcome.response}};
    }

    json pull(const json& body, int& status) {
        const long long after_seq = get_int(body, "after_seq");
        const long long limit = get_int(body, "limit", 50);
        auto outcome = call_sync(client_, "message.pull", {{"after_seq", after_seq}, {"limit", limit}});
        if (!outcome.result.ok()) {
            status = 500;
            return json{{"ok", false}, {"error_code", result_code(outcome.result)}, {"error_message", outcome.result.message()}};
        }
        for (const auto& msg : outcome.response.value("messages", json::array())) {
            store_inbox_item(normalize_message(msg, true, ""));
        }
        return json{{"ok", true}, {"result", outcome.response}};
    }

    json inbox(const std::string& path) {
        auto query = parse_query(path);
        auto items = snapshot(inbox_);
        return json{{"received", !filter_items(items, query).empty()}, {"items", filter_items(items, query)}};
    }

    json group_create(const json& body, int& status) {
        const std::string trace_id = first_non_empty({get_string(body, "trace_id"), random_hex()});
        const std::string name = first_non_empty({get_string(body, "name"), "cross-sdk-" + trace_id.substr(0, std::min<size_t>(8, trace_id.size()))});
        json params = {{"name", name}, {"visibility", first_non_empty({get_string(body, "visibility"), "private"})}};
        auto outcome = call_sync(client_, "group.create", params);
        if (!outcome.result.ok()) {
            status = 500;
            json out = json{{"ok", false}, {"trace_id", trace_id}, {"error_code", result_code(outcome.result)}, {"error_message", outcome.result.message()}};
            record_trace(trace_id, json{{"stage", "group_create_error"}, {"error", out}});
            return out;
        }
        const std::string group_id = extract_group_id(outcome.response);
        if (group_id.empty()) {
            status = 500;
            return json{{"ok", false}, {"trace_id", trace_id}, {"error_code", "missing_group_id"}, {"error_message", "group.create did not return group_id"}};
        }
        json add_results = json::array();
        if (body.contains("members") && body["members"].is_array()) {
            for (const auto& member : body["members"]) {
                const std::string member_aid = string_value(member);
                if (member_aid.empty() || member_aid == aid_) continue;
                auto add = call_sync(client_, "group.add_member", {{"group_id", group_id}, {"aid", member_aid}, {"role", "member"}});
                if (!add.result.ok()) {
                    status = 500;
                    return json{{"ok", false}, {"trace_id", trace_id}, {"group_id", group_id}, {"error_code", result_code(add.result)}, {"error_message", add.result.message()}};
                }
                add_results.push_back(add.response);
            }
        }
        json out = {{"ok", true}, {"trace_id", trace_id}, {"group_id", group_id}, {"create_result", outcome.response}, {"add_results", add_results}};
        record_trace(trace_id, json{{"stage", "group_create"}, {"group_id", group_id}, {"result", out}});
        return out;
    }

    json group_ready(const std::string& path, int& status) {
        auto query = parse_query(path);
        const std::string group_id = query["group_id"];
        if (group_id.empty()) {
            status = 400;
            return json{{"ok", false}, {"ready", false}, {"error_code", "bad_request"}, {"error_message", "group_id is required"}};
        }
        auto expected = split_csv(query["members"].empty() ? aid_ : query["members"]);
        auto outcome = call_sync(client_, "group.v2.bootstrap", {{"group_id", group_id}});
        if (!outcome.result.ok()) {
            status = 500;
            return json{{"ok", false}, {"ready", false}, {"error_code", result_code(outcome.result)}, {"error_message", outcome.result.message()}};
        }
        std::vector<std::string> committed;
        if (outcome.response.contains("committed_member_aids")) {
            committed = json_string_array(outcome.response["committed_member_aids"]);
        } else {
            committed = json_string_array(outcome.response.value("member_aids", json::array()));
        }
        std::vector<std::string> device_aids;
        for (const auto& device : outcome.response.value("devices", json::array())) {
            const std::string aid = get_string(device, "aid");
            if (!aid.empty()) device_aids.push_back(aid);
        }
        const bool membership_ok = contains_all(committed, expected);
        const bool devices_ok = !env_bool("CROSS_SDK_GROUP_READY_REQUIRE_DEVICES", true) || contains_all(device_aids, expected);
        return json{
            {"ok", true},
            {"ready", membership_ok && devices_ok},
            {"group_id", group_id},
            {"expected", expected},
            {"committed_member_aids", unique_sorted(committed)},
            {"device_aids", unique_sorted(device_aids)},
            {"pending_adds", outcome.response.value("pending_adds", json::array())},
            {"bootstrap", outcome.response},
        };
    }

    json group_send(const json& body, int& status) {
        const std::string trace_id = first_non_empty({get_string(body, "trace_id"), random_hex()});
        const std::string message_id = first_non_empty({get_string(body, "message_id"), trace_id + "-" + random_hex().substr(0, 8)});
        const std::string group_id = get_string(body, "group_id");
        const std::string text = get_string(body, "text");
        const bool e2ee = get_bool(body, "e2ee", true);
        if (group_id.empty()) {
            status = 400;
            return json{{"ok", false}, {"error_code", "bad_request"}, {"error_message", "group_id is required"}};
        }
        json payload = {
            {"type", "text"},
            {"text", text},
            {"trace_id", trace_id},
            {"case_id", first_non_empty({get_string(body, "case_id"), trace_id})},
        };
        auto outcome = call_sync(client_, "group.send", {
            {"group_id", group_id},
            {"payload", payload},
            {"encrypt", e2ee},
            {"message_id", message_id},
        }, timeout_seconds(body));
        if (!outcome.result.ok()) {
            status = 500;
            json out = json{{"ok", false}, {"trace_id", trace_id}, {"group_id", group_id}, {"message_id", message_id}, {"encrypted", e2ee}, {"error_code", result_code(outcome.result)}, {"error_message", outcome.result.message()}};
            record_trace(trace_id, json{{"stage", "group_send_error"}, {"group_id", group_id}, {"message_id", message_id}, {"error", out}});
            return out;
        }
        json out = {
            {"ok", true},
            {"trace_id", trace_id},
            {"group_id", group_id},
            {"message_id", message_id},
            {"seq", get_int(outcome.response, "seq", get_int(outcome.response, "message_seq"))},
            {"encrypted", e2ee},
            {"result", outcome.response},
        };
        record_trace(trace_id, json{{"stage", "group_send"}, {"group_id", group_id}, {"message_id", message_id}, {"result", out}});
        return out;
    }

    json group_pull(const json& body, int& status) {
        const std::string group_id = get_string(body, "group_id");
        const long long after_seq = get_int(body, "after_seq");
        const long long limit = get_int(body, "limit", 50);
        if (group_id.empty()) {
            status = 400;
            return json{{"ok", false}, {"error_code", "bad_request"}, {"error_message", "group_id is required"}};
        }
        auto outcome = call_sync(client_, "group.pull", {
            {"group_id", group_id},
            {"after_seq", after_seq},
            {"after_message_seq", after_seq},
            {"limit", limit},
        });
        if (!outcome.result.ok()) {
            status = 500;
            return json{{"ok", false}, {"group_id", group_id}, {"error_code", result_code(outcome.result)}, {"error_message", outcome.result.message()}};
        }
        for (const auto& msg : outcome.response.value("messages", json::array())) {
            store_group_inbox_item(normalize_group_message(msg, true, ""));
        }
        return json{{"ok", true}, {"group_id", group_id}, {"result", outcome.response}};
    }

    json group_ack(const json& body, int& status) {
        const std::string group_id = get_string(body, "group_id");
        const long long seq = get_int(body, "seq", get_int(body, "msg_seq", get_int(body, "up_to_seq")));
        if (group_id.empty()) {
            status = 400;
            return json{{"ok", false}, {"error_code", "bad_request"}, {"error_message", "group_id is required"}};
        }
        json params = {{"group_id", group_id}};
        if (seq > 0) {
            params["msg_seq"] = seq;
            params["up_to_seq"] = seq;
        }
        auto outcome = call_sync(client_, "group.ack_messages", params);
        if (!outcome.result.ok()) {
            status = 500;
            return json{{"ok", false}, {"group_id", group_id}, {"seq", seq}, {"error_code", result_code(outcome.result)}, {"error_message", outcome.result.message()}};
        }
        return json{{"ok", true}, {"group_id", group_id}, {"seq", seq}, {"result", outcome.response}};
    }

    json group_inbox(const std::string& path) {
        auto query = parse_query(path);
        auto items = snapshot(group_inbox_);
        return json{{"received", !filter_items(items, query).empty()}, {"items", filter_items(items, query)}};
    }

    json trace(const std::string& trace_id) {
        std::lock_guard<std::mutex> lock(mu_);
        return json{{"trace_id", trace_id}, {"items", traces_[trace_id]}};
    }

    json normalize_message(const json& msg, bool decrypted, const std::string& error_code) {
        const json payload = msg.value("payload", json::object());
        json item = {
            {"trace_id", first_non_empty({get_string(payload, "trace_id"), get_string(msg, "trace_id")})},
            {"message_id", first_non_empty({get_string(msg, "message_id"), get_string(msg, "id")})},
            {"from", first_non_empty({get_string(msg, "from"), get_string(msg, "from_aid")})},
            {"to", first_non_empty({get_string(msg, "to"), get_string(msg, "to_aid"), aid_})},
            {"text", first_non_empty({get_string(payload, "text"), get_string(msg, "text")})},
            {"decrypted", decrypted},
            {"encrypted", get_bool(msg, "e2ee", false) || get_bool(msg, "encrypted", false)},
            {"seq", get_int(msg, "seq", get_int(msg, "message_seq"))},
            {"ack_seq", get_int(msg, "ack_seq")},
            {"error_code", error_code},
            {"raw_sha256", sha256_placeholder(msg)},
        };
        add_envelope_metadata(item, msg);
        return item;
    }

    json normalize_group_message(const json& msg, bool decrypted, const std::string& error_code) {
        const json payload = msg.value("payload", json::object());
        json item = {
            {"trace_id", first_non_empty({get_string(payload, "trace_id"), get_string(msg, "trace_id")})},
            {"group_id", get_string(msg, "group_id")},
            {"message_id", first_non_empty({get_string(msg, "message_id"), get_string(msg, "id")})},
            {"from", first_non_empty({get_string(msg, "from"), get_string(msg, "from_aid"), get_string(msg, "sender_aid")})},
            {"text", first_non_empty({get_string(payload, "text"), get_string(msg, "text")})},
            {"decrypted", decrypted},
            {"encrypted", get_bool(msg, "e2ee", false) || get_bool(msg, "encrypted", false)},
            {"seq", get_int(msg, "seq", get_int(msg, "message_seq", get_int(msg, "msg_seq")))},
            {"error_code", error_code},
            {"raw_sha256", sha256_placeholder(msg)},
        };
        add_envelope_metadata(item, msg);
        return item;
    }

    static void add_envelope_metadata(json& item, const json& msg) {
        json protected_headers = json::object();
        if (msg.contains("protected_headers") && msg["protected_headers"].is_object()) {
            protected_headers = msg["protected_headers"];
        } else if (msg.contains("e2ee") && msg["e2ee"].is_object() &&
                   msg["e2ee"].contains("protected_headers") && msg["e2ee"]["protected_headers"].is_object()) {
            protected_headers = msg["e2ee"]["protected_headers"];
        }
        std::string payload_type = get_string(msg, "payload_type");
        if (payload_type.empty() && protected_headers.is_object()) {
            payload_type = get_string(protected_headers, "payload_type");
        }
        if (payload_type.empty() && msg.contains("e2ee") && msg["e2ee"].is_object()) {
            payload_type = get_string(msg["e2ee"], "payload_type");
        }
        if (!payload_type.empty()) item["payload_type"] = payload_type;
        if (protected_headers.is_object() && !protected_headers.empty()) item["protected_headers"] = protected_headers;
    }

    void store_inbox_item(const json& item) {
        {
            std::lock_guard<std::mutex> lock(mu_);
            inbox_.push_back(item);
            if (inbox_.size() > 1000) inbox_.erase(inbox_.begin(), inbox_.end() - 1000);
        }
        record_trace(get_string(item, "trace_id"), json{{"stage", "receive"}, {"message", item}});
    }

    void store_group_inbox_item(const json& item) {
        {
            std::lock_guard<std::mutex> lock(mu_);
            group_inbox_.push_back(item);
            if (group_inbox_.size() > 1000) group_inbox_.erase(group_inbox_.begin(), group_inbox_.end() - 1000);
        }
        record_trace(get_string(item, "trace_id"), json{{"stage", "group_receive"}, {"message", item}});
    }

    void record_trace(const std::string& trace_id, const json& item) {
        if (trace_id.empty()) return;
        json entry = item;
        entry["ts"] = static_cast<long long>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        entry["language"] = language_;
        entry["aid"] = aid_;
        std::lock_guard<std::mutex> lock(mu_);
        traces_[trace_id].push_back(std::move(entry));
    }

    static int timeout_seconds(const json& body) {
        const long long ms = get_int(body, "timeout_ms", 30000);
        return static_cast<int>(std::max<long long>(5, (ms + 999) / 1000));
    }

    static json error_response(const std::string& trace_id, const std::string& message_id, bool encrypted, const Result& result) {
        return json{
            {"ok", false},
            {"trace_id", trace_id},
            {"message_id", message_id},
            {"encrypted", encrypted},
            {"error_code", result_code(result)},
            {"error_message", result.message()},
        };
    }

    static void erase_trace(std::vector<json>& items, const std::string& trace_id) {
        items.erase(std::remove_if(items.begin(), items.end(), [&](const json& item) {
            return get_string(item, "trace_id") == trace_id;
        }), items.end());
    }

    std::vector<json> snapshot(const std::vector<json>& items) {
        std::lock_guard<std::mutex> lock(mu_);
        return items;
    }

    static std::vector<json> filter_items(const std::vector<json>& items, const std::map<std::string, std::string>& query) {
        const std::string trace_id = query.count("trace_id") ? query.at("trace_id") : "";
        const std::string group_id = query.count("group_id") ? query.at("group_id") : "";
        const std::string from = query.count("from") ? query.at("from") : "";
        const int limit = query.count("limit") ? std::max(1, std::stoi(query.at("limit"))) : 20;
        std::vector<json> out;
        for (const auto& item : items) {
            if (!trace_id.empty() && get_string(item, "trace_id") != trace_id) continue;
            if (!group_id.empty() && get_string(item, "group_id") != group_id) continue;
            if (!from.empty() && get_string(item, "from") != from) continue;
            out.push_back(item);
        }
        if (static_cast<int>(out.size()) > limit) out.erase(out.begin(), out.end() - limit);
        return out;
    }

    static std::string url_decode(const std::string& input) {
        std::string out;
        for (size_t i = 0; i < input.size(); ++i) {
            if (input[i] == '%' && i + 2 < input.size()) {
                const std::string hex = input.substr(i + 1, 2);
                char* end = nullptr;
                long value = std::strtol(hex.c_str(), &end, 16);
                if (end && *end == '\0') {
                    out.push_back(static_cast<char>(value));
                    i += 2;
                    continue;
                }
            }
            out.push_back(input[i] == '+' ? ' ' : input[i]);
        }
        return out;
    }

    static std::map<std::string, std::string> parse_query(const std::string& path) {
        std::map<std::string, std::string> out;
        const auto qpos = path.find('?');
        if (qpos == std::string::npos) return out;
        std::stringstream ss(path.substr(qpos + 1));
        std::string pair;
        while (std::getline(ss, pair, '&')) {
            const auto eq = pair.find('=');
            const std::string key = url_decode(pair.substr(0, eq));
            const std::string value = eq == std::string::npos ? "" : url_decode(pair.substr(eq + 1));
            out[key] = value;
        }
        return out;
    }

    static std::string path_only(const std::string& path) {
        const auto qpos = path.find('?');
        return qpos == std::string::npos ? path : path.substr(0, qpos);
    }

    static std::vector<std::string> split_csv(const std::string& value) {
        std::vector<std::string> out;
        std::stringstream ss(value);
        std::string item;
        while (std::getline(ss, item, ',')) {
            if (!item.empty()) out.push_back(item);
        }
        return out;
    }

    static std::vector<std::string> json_string_array(const json& value) {
        std::vector<std::string> out;
        if (!value.is_array()) return out;
        for (const auto& item : value) {
            const auto s = string_value(item);
            if (!s.empty()) out.push_back(s);
        }
        return out;
    }

    static std::vector<std::string> unique_sorted(std::vector<std::string> items) {
        std::sort(items.begin(), items.end());
        items.erase(std::unique(items.begin(), items.end()), items.end());
        return items;
    }

    static bool contains_all(std::vector<std::string> haystack, const std::vector<std::string>& needles) {
        haystack = unique_sorted(std::move(haystack));
        for (const auto& needle : needles) {
            if (!std::binary_search(haystack.begin(), haystack.end(), needle)) return false;
        }
        return true;
    }

    static std::string extract_group_id(const json& result) {
        if (result.contains("group_id")) return get_string(result, "group_id");
        if (result.contains("group") && result["group"].is_object()) {
            const auto gid = get_string(result["group"], "group_id");
            if (!gid.empty()) return gid;
        }
        if (result.contains("member") && result["member"].is_object()) {
            const auto gid = get_string(result["member"], "group_id");
            if (!gid.empty()) return gid;
        }
        return "";
    }

    std::string language_;
    std::string sdk_version_;
    std::string aid_;
    std::string issuer_;
    std::string gateway_url_;
    std::string slot_id_;
    std::string aun_path_;
    bool debug_ = false;
    std::shared_ptr<AUNClient> client_;
    bool ready_ = false;
    std::string startup_error_;
    std::vector<json> inbox_;
    std::vector<json> group_inbox_;
    std::map<std::string, std::vector<json>> traces_;
    std::map<std::string, json> send_results_;
    std::vector<Subscription> subscriptions_;
    std::mutex mu_;
};

struct HttpRequest {
    std::string method;
    std::string path;
    std::string body;
};

bool read_http_request(int fd, HttpRequest& request) {
    std::string data;
    char buffer[4096];
    while (data.find("\r\n\r\n") == std::string::npos) {
        ssize_t n = recv(fd, buffer, sizeof(buffer), 0);
        if (n <= 0) return false;
        data.append(buffer, buffer + n);
        if (data.size() > 1024 * 1024) return false;
    }
    const auto header_end = data.find("\r\n\r\n");
    const std::string headers = data.substr(0, header_end);
    std::stringstream hs(headers);
    hs >> request.method >> request.path;
    std::string line;
    size_t content_length = 0;
    while (std::getline(hs, line)) {
        std::string lower = line;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower.find("content-length:") == 0) {
            content_length = static_cast<size_t>(std::stoul(lower.substr(std::string("content-length:").size())));
        }
    }
    request.body = data.substr(header_end + 4);
    while (request.body.size() < content_length) {
        ssize_t n = recv(fd, buffer, sizeof(buffer), 0);
        if (n <= 0) return false;
        request.body.append(buffer, buffer + n);
    }
    if (request.body.size() > content_length) request.body.resize(content_length);
    return true;
}

void write_http_response(int fd, int status, const json& body) {
    const std::string text = body.dump();
    std::string status_text = status == 200 ? "OK" : (status == 404 ? "Not Found" : "Error");
    std::ostringstream out;
    out << "HTTP/1.1 " << status << " " << status_text << "\r\n"
        << "Content-Type: application/json; charset=utf-8\r\n"
        << "Content-Length: " << text.size() << "\r\n"
        << "Connection: close\r\n\r\n"
        << text;
    const std::string response = out.str();
    send(fd, response.data(), response.size(), 0);
}

void handle_client(int fd, CrossSdkCppAgent& agent) {
    HttpRequest request;
    if (!read_http_request(fd, request)) {
        close(fd);
        return;
    }
    json body = json::object();
    if (!request.body.empty()) {
        try { body = json::parse(request.body); } catch (...) { body = json::object(); }
    }
    int status = 200;
    const auto response = agent.Handle(request.method, request.path, body, status);
    write_http_response(fd, status, response);
    close(fd);
}

} // namespace

int main() {
    CrossSdkCppAgent agent;
    std::thread starter([&agent]() {
        agent.Start();
    });
    starter.detach();

    const std::string host = env_string("AUN_CONTROL_HOST", "0.0.0.0");
    const int port = std::stoi(env_string("AUN_CONTROL_PORT", "9001"));

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cerr << "socket failed\n";
        return 1;
    }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<uint16_t>(port));
    address.sin_addr.s_addr = host == "0.0.0.0" ? INADDR_ANY : inet_addr(host.c_str());
    if (bind(server_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
        std::cerr << "bind failed\n";
        return 1;
    }
    if (listen(server_fd, 64) < 0) {
        std::cerr << "listen failed\n";
        return 1;
    }
    std::cout << "cross-sdk cpp agent listening on " << host << ":" << port << std::endl;
    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) continue;
        std::thread(handle_client, client_fd, std::ref(agent)).detach();
    }
    agent.Close();
    return 0;
}
