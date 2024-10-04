#include <cstdio>
#include <string>

#include "syslog.hpp"

int main()
{
    SyslogMessageFormatter messageFormatter;
    const auto message1 = messageFormatter.format(Facility::USER, Severity::S_INFO, "TestId1", "", "This is a test message1");
    const auto message2 = messageFormatter.format(Facility::KERNEL, Severity::S_ALERT, "TestHostName", "testAppName", "", "TestId2", "", "This is a test message2");

    SyslogTLSClient syslogClient("127.0.0.1", "6514", "C:\\testProject\\syslog\\build\\src\\Debug\\ssl\\certs\\syslog-watcher-server.crt");
    bool result = syslogClient.sendSyslogMessage(message1);
    if  (!result)
    {
        std::printf("Failed to send message1\n");
    }

    result = syslogClient.sendSyslogMessage(message2);
    if  (!result)
    {
        std::printf("Failed to send message2\n");
    }

    return 0;
}