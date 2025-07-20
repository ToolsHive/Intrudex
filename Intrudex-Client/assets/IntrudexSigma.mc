; IntrudexSigma.mc - Message file for IntrudexSigma Event Log source

MessageIdTypedef=DWORD

SeverityNames=(Success=0x0:STATUS_SEVERITY_SUCCESS
               Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
               Warning=0x2:STATUS_SEVERITY_WARNING
               Error=0x3:STATUS_SEVERITY_ERROR)

FacilityNames=(System=0x0
               Application=0x1)

LanguageNames=(English=0x409:MSG00409)

; // Message Definitions

MessageId=0x1000
Severity=Informational
Facility=Application
SymbolicName=INTRUDEXSIGMA_EVENT
Language=English
Sigma Event: %1
.
