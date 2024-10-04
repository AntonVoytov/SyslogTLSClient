#include <cstdio>
#include <cstdint>
#include <string>
#include <chrono>
#include <ctime>
#include <format>
#include <filesystem>
#include <thread>

#include <windows.h>

#include "syslog.hpp"

std::string getLastErrorAsString()
{
    const DWORD errorMessageID = ::GetLastError();
    if (errorMessageID == 0ul)
    {
        std::printf("No error\n");
        return {};
    }

    LPSTR messageBuffer = nullptr;
    const auto size = static_cast<size_t>(FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                                         nullptr,
                                                         errorMessageID,
                                                         MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                                         messageBuffer,
                                                         0,
                                                         nullptr));

    if (size == 0ull)
    {
        std::printf("Failed to format error string\n");
        return {};
    }

    const std::string message(messageBuffer, size);
    if (LocalFree(messageBuffer) != nullptr)
    {
        std::printf("Failed to free error string buffer");
    }

    return message;
}

const uint8_t SyslogMessageFormatter::syslogVersion_ = 1;

SyslogMessageFormatter::SyslogMessageFormatter()
    : isInitialized_(false)
{}

std::string SyslogMessageFormatter::format(const Facility facility, const Severity severity,
                                           const std::string & hostName, const std::string & appName,
                                           const std::string & processId, const std::string & messageId,
                                           const std::string & structuredData, const std::string & message)
{
    if (!initialize())
    {
        return {};
    }

    const auto priority = static_cast<uint8_t>(facility) * 8 + static_cast<uint8_t>(severity);
    return std::format("<{}>{} {} {} {} {} {} {} {}",
                       priority,
                       syslogVersion_,
                       getTimeStamp().c_str(),
                       hostName.empty()         ? "-" : hostName.c_str(),
                       appName.empty()          ? "-" : appName.c_str(),
                       processId.empty()        ? "-" : processId.c_str(),
                       messageId.empty()        ? "-" : messageId.c_str(),
                       structuredData.empty()   ? "-" : structuredData.c_str(),
                       message.c_str());
}

std::string SyslogMessageFormatter::format(const Facility facility, const Severity severity,
                                           const std::string & messageId, const std::string & structuredData,
                                           const std::string & message)
{
    if (!initialize())
    {
        return {};
    }

    const auto priority = static_cast<uint8_t>(facility) * 8 + static_cast<uint8_t>(severity);
    return std::format("<{}>{} {} {} {} {} {} {} {}",
                       priority,
                       syslogVersion_,
                       getTimeStamp().c_str(),
                       hostName_.c_str(),
                       appName_.c_str(),
                       processId_.c_str(),
                       messageId.empty() ? "-" : messageId.c_str(),
                       structuredData.empty() ? "-" : structuredData.c_str(),
                       message.c_str());
}

bool SyslogMessageFormatter::initialize()
{
    if (isInitialized_)
    {
        return isInitialized_;
    }

    DWORD hostNameSize = MAX_COMPUTERNAME_LENGTH + 1;
    hostName_.resize(static_cast<size_t>(hostNameSize));
    if (GetComputerNameA(hostName_.data(), &hostNameSize) == FALSE)
    {
        std::printf("Failed to get computer name. Reason - %s\n", getLastErrorAsString().c_str());
        return isInitialized_;
    }

    DWORD appNameSize = MAX_PATH;
    do
    {
        appName_.resize(appNameSize);
        appNameSize = GetModuleFileNameA(nullptr, appName_.data(), static_cast<DWORD>(appName_.size()));
        if (appNameSize == 0ul)
        {
            std::printf("Failed to get application name. Reason - %s\n", getLastErrorAsString().c_str());
            return isInitialized_;
        }

        if (appNameSize == appName_.size())
        {
            appNameSize *= 2;
            continue;
        }

        appName_ = std::filesystem::path(appName_).filename().string();
    }
    while (false);

    processId_ = std::to_string(GetCurrentProcessId());

    isInitialized_ = true;
    return isInitialized_;
}

std::string SyslogMessageFormatter::getTimeStamp() const
{
    const auto now = std::chrono::system_clock::now();
    const auto currentTime = std::chrono::system_clock::to_time_t(now);
    tm currentTimeUTC;
    gmtime_s(&currentTimeUTC, &currentTime);
    const auto miliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now - std::chrono::time_point_cast<std::chrono::seconds>(now));
    return std::format("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
                       currentTimeUTC.tm_year + 1900,
                       currentTimeUTC.tm_mon + 1,
                       currentTimeUTC.tm_mday,
                       currentTimeUTC.tm_hour,
                       currentTimeUTC.tm_min,
                       currentTimeUTC.tm_sec,
                       miliseconds.count());
}

SyslogTLSClient::SyslogTLSClient(const std::string & serverIP, const std::string & port,
                                 const std::string & serverCertPath, const std::string & clientCertPath)
    : serverCertPath_(serverCertPath)
    , clientCertPath_(clientCertPath)
    , serverIP_(serverIP)
    , port_(port)
    , ssl_(nullptr)
    , ctx_(nullptr)
    , bio_(nullptr)
    , isInitialized_(false)
    , isConnected_(false)
{}

SyslogTLSClient::~SyslogTLSClient()
{
    cleanup();
}

bool SyslogTLSClient::sendSyslogMessage(const std::string & message)
{
    do
    {
        if (!initialize())
        {
            return false;
        }

        if (!connect())
        {
            return false;
        }

        if (BIO_write(bio_, message.c_str(), static_cast<int>(message.size()) + 1) <= 0)
        {
            std::printf("Failed to send syslog message. Reason - %s\n", ERR_reason_error_string(ERR_get_error()));
            std::printf("Trying to reconnect to send message\n");
            cleanup();
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
    }
    while (false);

    return true;
}

bool SyslogTLSClient::initialize()
{
    if (isInitialized_)
    {
        return isInitialized_;
    }

    if (OSSL_PROVIDER_load(nullptr, "default") == nullptr)
    {
        std::printf("Failed to load default provider. Reason - %s\n", ERR_reason_error_string(ERR_get_error()));
        return isInitialized_;
    }

    ctx_ = SSL_CTX_new(TLS_client_method());
    if (ctx_ == nullptr)
    {
        std::printf("Failed to create SSL context. Reason - %s\n", ERR_reason_error_string(ERR_get_error()));
        return isInitialized_;
    }

    if (SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION) == 0)
    {
        std::printf("Failed to set min proto version. Reason - %s\n", ERR_reason_error_string(ERR_get_error()));
        return isInitialized_;
    }

    if (SSL_CTX_set_max_proto_version(ctx_, TLS1_3_VERSION) == 0)
    {
        std::printf("Failed to set max proto version. Reason - %s\n", ERR_reason_error_string(ERR_get_error()));
        return isInitialized_;
    }

    if (!std::filesystem::exists(serverCertPath_))
    {
        std::printf("Server sertification file does not exist by this path - %s\n", serverCertPath_.c_str());
        return isInitialized_;
    }

    if (SSL_CTX_load_verify_locations(ctx_, serverCertPath_.c_str(), NULL) == 0)
    {
        std::printf("Failed to load CA certificates. Reason - %s\n", ERR_reason_error_string(ERR_get_error()));
        return isInitialized_;
    }

    /*For mutual handshake*/
    if (std::filesystem::exists(clientCertPath_))
    {
        if (SSL_CTX_use_certificate_file(ctx_, clientCertPath_.c_str(), SSL_FILETYPE_PEM) == 0)
        {
            std::printf("Failed to load client certificate. Reason - %s\n", ERR_reason_error_string(ERR_get_error()));
            return false;
        }

        const std::string privateKeyFilePath = std::filesystem::path(clientCertPath_).replace_extension("key").string();
        if (SSL_CTX_use_PrivateKey_file(ctx_, privateKeyFilePath.c_str(), SSL_FILETYPE_PEM) == 0)
        {
            std::printf("Failed to load client private key. Reason - %s\n", ERR_reason_error_string(ERR_get_error()));
            return false;
        }

        if (SSL_CTX_check_private_key(ctx_) == 0)
        {
            std::printf("Client private key does not match certificate. Reason - %s\n", ERR_reason_error_string(ERR_get_error()));
            return false;
        }
    }

    isInitialized_ = true;
    return isInitialized_;
}

bool SyslogTLSClient::connect()
{
    if (isConnected_)
    {
        return isConnected_;
    }

    bio_ = BIO_new_ssl_connect(ctx_);
    if (bio_ == nullptr)
    {
        std::printf("Failed to create BIO object. Reason - %s\n", ERR_reason_error_string(ERR_get_error()));
        return false;
    }

    if (BIO_get_ssl(bio_, &ssl_) == 0)
    {
        std::printf("Failed to retrieve SSL object. Reason - %s\n", ERR_reason_error_string(ERR_get_error()));
        return false;
    }

    if (SSL_set_tlsext_host_name(ssl_, serverIP_.c_str()) == 0)
    {
        std::printf("Failed to set tls host name. Reason - %s\n", ERR_reason_error_string(ERR_get_error()));
        return false;
    }

    const std::string bioAddress = serverIP_ + ":" + port_;
    if (BIO_set_conn_hostname(bio_, bioAddress.c_str()) == 0)
    {
        std::printf("Failed to set connection hostname to BIO object. Reason - %s\n", ERR_reason_error_string(ERR_get_error()));
        return false;
    }

    SSL_set_verify(ssl_, SSL_VERIFY_PEER, nullptr);
    if (BIO_do_connect(bio_) <= 0)
    {
        std::printf("Failed to establish TLS connection. Reason - %s\n", ERR_reason_error_string(ERR_get_error()));
        return false;
    }

    if (BIO_do_handshake(bio_) <= 0)
    {
        std::printf("Failed to complete TLS handshake. Reason - %s\n", ERR_reason_error_string(ERR_get_error()));
        return false;
    }

    if (SSL_get_verify_result(ssl_) != X509_V_OK)
    {
        std::printf("Failed to verify server certificate. Reason - %s\n", ERR_reason_error_string(ERR_get_error()));
        return false;
    }

    isConnected_ = true;
    return isConnected_;
}

void SyslogTLSClient::cleanup()
{
    if (bio_ == nullptr)
    {
        BIO_free_all(bio_);
        bio_ = nullptr;
    }

    if (ctx_ == nullptr)
    {
        SSL_CTX_free(ctx_);
        ctx_ = nullptr;
    }

    ssl_ = nullptr;
    isConnected_ = false;
    isInitialized_ = false;
}