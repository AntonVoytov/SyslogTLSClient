#ifndef _SYSLOG_H_
#define _SYSLOG_H_

#include <cstdio>
#include <cstdint>
#include <string>
#include <chrono>
#include <ctime>
#include <format>
#include <filesystem>
#include <thread>

#include <windows.h>

#define OPENSSL_API_COMPAT 30300    // Compatibility with OpenSSL 3.3.0 (including 3.3.1)
#define OPENSSL_NO_DEPRECATED       // Disable deprecated functions

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>

enum class Facility
{
    KERNEL = 0,     /* kernel messages */
    USER,           /* random user-level messages */
    MAIL,           /* mail system */
    DAEMON,         /* system daemons */
    AUTH,           /* security/authorization messages */
    SYSLOG,         /* messages generated internally by syslogd */
    LPR,            /* line printer subsystem */
    NEWS,           /* network news subsystem */
    UUCP,           /* UUCP subsystem */
    CRON,           /* clock daemon */
    AUTHPRIV,       /* security/authorization messages (private) */
    FTP,            /* ftp daemon */
    LOCAL0,         /* reserved for local use */
    LOCAL1,         /* reserved for local use */
    LOCAL2,         /* reserved for local use */
    LOCAL3,         /* reserved for local use */
    LOCAL4,         /* reserved for local use */
    LOCAL5,         /* reserved for local use */
    LOCAL6,         /* reserved for local use */
    LOCAL7          /* reserved for local use */
};

enum class Severity
{
    S_EMERGENCY = 0,    /* system is unusable */
    S_ALERT,            /* action must be taken immediately */
    S_CRITICAL,         /* critical conditions */
    S_ERROR,            /* error conditions */
    S_WARNING,          /* warning conditions */
    S_NOTICE,           /* normal but significant condition */
    S_INFO,             /* informational */
    S_DEBUG             /* debug-level messages */
};

class SyslogMessageFormatter
{
public:
    SyslogMessageFormatter();
    ~SyslogMessageFormatter() = default;

    SyslogMessageFormatter(const SyslogMessageFormatter &) = delete;
    SyslogMessageFormatter & operator=(const SyslogMessageFormatter &) = delete;

    SyslogMessageFormatter(SyslogMessageFormatter &&) = delete;
    SyslogMessageFormatter & operator=(SyslogMessageFormatter &&) = delete;

    /**
     * @brief Formats a syslog message according to RFC 5424.
     *
     * This function constructs a complete syslog message by taking in various fields, such as
     * facility, severity, hostname, app name, process ID, message ID, structured data, and the
     * actual log message content. The message is formatted to adhere to the RFC 5424 standard.
     *
     * @param facility The facility code representing the source of the message (e.g., kernel, mail system).
     * @param severity The severity level of the message (e.g., error, informational).
     * @param hostName The hostname of the machine generating the message. (optional pass empty string)
     * @param appName The name of the application generating the log message. (optional pass empty string)
     * @param processId The process ID of the application or system component. (optional pass empty string)
     * @param messageId The message ID to identify the log type or category. (optional pass empty string)
     * @param structuredData Additional structured data related to the event (formatted key-value pairs). (optional pass empty string)
     * @param message The actual message content or log entry.
     * @return A formatted syslog message as a string, compliant with RFC 5424.
     */
    std::string format(const Facility facility, const Severity severity,
                       const std::string & hostName, const std::string & appName,
                       const std::string & processId, const std::string & messageId,
                       const std::string & structuredData, const std::string & message);

    /**
     * @brief Formats a syslog message with fewer fields for simplicity, omitting host and app-specific data.
     *
     * This version of `formatMessage` is a simplified format where host name, application name and process ID created by SyslogMessageFormatter class.
     *
     * @param facility The facility code representing the source of the message (e.g., kernel, mail system).
     * @param severity The severity level of the message (e.g., error, informational).
     * @param messageId The message ID to identify the log type or category. (optional pass empty string)
     * @param structuredData Additional structured data related to the event (formatted key-value pairs). (optional pass empty string)
     * @param message The actual message content or log entry.
     * @return A formatted syslog message as a string, compliant with RFC 5424.
     */
    std::string format(const Facility facility, const Severity severity,
                       const std::string & messageId, const std::string & structuredData,
                       const std::string & message);

private:
    bool initialize();
    std::string getTimeStamp() const;

private:
    static const uint8_t syslogVersion_;
    std::string hostName_;
    std::string appName_;
    std::string processId_;
    bool isInitialized_;
};

class SyslogTLSClient
{
public:
    explicit SyslogTLSClient(const std::string & serverIP, const std::string & port,
                             const std::string & rootCertPath, const std::string & clientCertPath,
                             const int depth);
    ~SyslogTLSClient();

    SyslogTLSClient() = delete;
    SyslogTLSClient(const SyslogTLSClient &) = delete;
    SyslogTLSClient & operator=(const SyslogTLSClient &) = delete;

    SyslogTLSClient(SyslogTLSClient &&) = delete;
    SyslogTLSClient & operator=(SyslogTLSClient &&) = delete;

    /**
     * @brief Sends a syslog message to the configured server.
     *
     * This method establishes a connection with the syslog server if not already connected,
     * and sends the specified message. If the connection fails, it attempts to reconnect 
     * before sending the message.
     *
     * @param message The syslog message to be sent. This should be a properly formatted 
     *                syslog message string.
     * 
     * @param message Number of retries to send message. -1 infinite retries.
     * 
     * @return true if the message was successfully sent, false otherwise.
     * 
     * @note Ensure that the server address and port are correctly configured before calling 
     *       this method. If the connection to the server is lost during the sending process, 
     *       the method will attempt to reconnect and resend the message.
     */
    bool sendSyslogMessage(const std::string & message, int retries = -1);

private:
    bool initialize();
    bool connect();
    void cleanup();
    bool setProtocolVersion();
    bool setClientCertificate();
    bool setVerifyServerCertificate();
    bool connectAndHandshake();
    bool internalSend(const std::string & message, int & retries);

private:
    std::string rootCertPath_;
    std::string clientCertPath_;
    std::string serverIP_;
    std::string port_;
    SSL_CTX * ctx_;
    SSL * ssl_;
    BIO * bio_;

    int depth_;

    bool isInitialized_;
    bool isConnected_;
};

#endif//_SYSLOG_H