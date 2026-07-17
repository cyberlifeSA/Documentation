
## Sources Clasificados

| Category                                                         | Lo primero que pienso   |
| ---------------------------------------------------------------- | ----------------------- |
| Cisco - Endpoint Network Visibility (Network Flow)               | `cisconvmflowdata`      |
| Operative System Information                                     | `operatingsystem`       |
| API de Microsoft 365                                             | `ms_o365_message_trace` |
| Logs DNS almacenados y enviados a Splunk                         | `lambda:dns`            |
| Security & Authentication Logs (RHEL CentOS Fedora Amazon Linux) | `/var/log/secure`       |
| Authentication file of linux based on Debian and Ubuntu (Auth)   | `/var/log/auth.log`     |
| Install, Update or deleting Software                             | `package`               |

## SourceTypes Clasificados

| Category                                                                   | Lo primero que pienso                                 |
| -------------------------------------------------------------------------- | ----------------------------------------------------- |
| IAM (Access, Errors ...)                                                   | `aws:cloudtrail`                                      |
| EC2                                                                        | `aws:cloudtrail`                                      |
| EC2 Provisionamiento / Inicialización de instancias                        | `cloud-init-output`                                   |
| S3 API                                                                     | `aws:cloudtrail`                                      |
| MFA AWS                                                                    | `aws:clodtrail`                                       |
| S3 Access Logs (Bucket/Object/Operations)                                  | `aws:s3:accesslogs`                                   |
| DNS                                                                        | `stream:dns`                                          |
| HTTP                                                                       | `stream:http`                                         |
| SMTP (Mail)                                                                | `stream:smtp`                                         |
| Microsoft 365 Reporting Following Messages                                 | `ms:o365:reporting:messagetrace`                      |
| Microsoft 365 (Audit Logs - Managment Logs (Activities))                   | `o365:management:activity`                            |
| Procesos Windows                                                           | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| Hardware Information                                                       | `hardware`                                            |
| Monitor Host Windows State (Microsoft Windows)                             | `winhostmon`                                          |
| Telemetry / Endpoint Inventory                                             | `osquery:results`                                     |
| Log source (Without Parsing(Transport))                                    | `sysmon`                                              |
| Symantec Endpoint Protection (Antivirus - Security Log)                    | `symantec:ep:security:file`                           |
| Security Logs Windows (Important)                                          | `WinEventLog:Security`                                |
| Microsoft Entra ID (Sign-in Logs / Azure AD)                               | `ms:aad:signin`                                       |
| Linux Security Logs - Events from: `/var/log/secure` & `/var/log/auth.log` | `linux_secure`                                        |
| Managment acions and auditory from Microsoft 365 (Sysmon)                  | `ms:o365:management`                                  |



*Nota*
`sourcetype="WinEventLog:Security"`
Windows
│
├── Application
├── Security
├── System
├── Setup
└── ForwardedEvents