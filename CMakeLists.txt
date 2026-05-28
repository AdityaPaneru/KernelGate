cmake_minimum_required(VERSION 3.20)
project(KernelGate LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(nlohmann_json REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

add_executable(kernelgate-agent
    src/main.cpp
    src/Event.cpp
    src/PolicyLoader.cpp
    src/RiskEvaluator.cpp
    src/Incident.cpp
    src/Correlator.cpp
    src/AuditStore.cpp
    src/ProcEnricher.cpp
    src/RunContext.cpp
    src/UemClient.cpp
)

target_include_directories(kernelgate-agent
    PRIVATE
    include
)

target_link_libraries(kernelgate-agent
    PRIVATE
    nlohmann_json::nlohmann_json
    SQLite::SQLite3
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
)


add_executable(kernelgate-fanotify-demo
    src/fanotify_demo.cpp
    src/Event.cpp
    src/PolicyLoader.cpp
    src/RiskEvaluator.cpp
    src/Incident.cpp
    src/Correlator.cpp
    src/AuditStore.cpp
    src/ProcEnricher.cpp
    src/RunContext.cpp
    src/FileTelemetry.cpp
)

target_include_directories(kernelgate-fanotify-demo
    PRIVATE
    include
)

target_link_libraries(kernelgate-fanotify-demo
    PRIVATE
    nlohmann_json::nlohmann_json
    SQLite::SQLite3
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
)
