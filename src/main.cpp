#include "syslog.hpp"

int main()
{
    SyslogMessageFormatter messageFormatter;
    const auto message1 = messageFormatter.format(Facility::USER, Severity::S_INFO, "TestId1", "", "This is a test message1");
    const auto message2 = messageFormatter.format(Facility::KERNEL, Severity::S_ALERT, "TestHostName", "testAppName", "", "TestId2", "", "This is a test message2");

    SyslogTLSClient syslogClient("172.31.68.201", "6514",
                                 "C:\\testProject\\SyslogTLSClient\\cert_linux\\rootCA.crt",
                                 "C:\\testProject\\SyslogTLSClient\\cert_linux\\client.crt",
                                 "C:\\testProject\\SyslogTLSClient\\cert_linux\\client.key",
                                 20);
    bool result = syslogClient.sendSyslogMessage(message1, 5);
    if  (!result)
    {
        std::printf("Failed to send message1\n");
    }

    result = syslogClient.sendSyslogMessage(message2);
    if  (!result)
    {
        std::printf("Failed to send message2\n");
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));
    return 0;
}