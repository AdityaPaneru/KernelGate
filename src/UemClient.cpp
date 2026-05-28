#include "UemClient.hpp"

#include <curl/curl.h>
#include <iostream>
#include <utility>

namespace {

std::size_t discardResponseBody(
    char* ptr,
    std::size_t size,
    std::size_t nmemb,
    void* userdata
) {
    (void)ptr;
    (void)userdata;
    return size * nmemb;
}

} // namespace

namespace kernelgate {

UemClient::UemClient(std::string base_url)
    : base_url_(std::move(base_url)) {}

std::string UemClient::buildIncidentPayload(
    const Incident& incident,
    const std::string& run_id,
    const std::string& device_id
) {
    nlohmann::json payload;

    payload["device_id"] = device_id;
    payload["run_id"] = run_id;
    payload["incident_id"] = incident.incident_id;
    payload["pid"] = incident.pid;
    payload["process_name"] = incident.process_name;
    payload["process_path"] = incident.process_path;
    payload["chain_summary"] = buildChainSummary(incident);
    payload["risk_score"] = incident.total_risk_score;
    payload["verdict"] = incident.verdict;
    payload["first_seen"] = incident.first_seen;
    payload["last_seen"] = incident.last_seen;

    payload["matched_rule_ids"] = nlohmann::json::array();

    for (const auto& match : incident.matched_rules) {
        payload["matched_rule_ids"].push_back(match.rule_id);
    }

    return payload.dump();
}

bool UemClient::uploadIncident(
    const Incident& incident,
    const std::string& run_id,
    const std::string& device_id
) const {
    CURL* curl = curl_easy_init();

    if (curl == nullptr) {
        std::cerr << "[UPLOAD] Failed to initialize CURL\n";
        return false;
    }

    const std::string url = base_url_ + "/incident";
    const std::string payload = buildIncidentPayload(
        incident,
        run_id,
        device_id
    );

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discardResponseBody);

    const CURLcode result = curl_easy_perform(curl);

    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (result != CURLE_OK) {
        std::cerr << "[UPLOAD] Failed: "
                  << curl_easy_strerror(result) << "\n";
        return false;
    }

    if (response_code < 200 || response_code >= 300) {
        std::cerr << "[UPLOAD] Server returned HTTP "
                  << response_code << "\n";
        return false;
    }

    std::cout << "[UPLOAD] Incident "
              << incident.incident_id
              << " uploaded to "
              << url
              << "\n";

    return true;
}

} // namespace kernelgate
