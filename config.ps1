# SystemAudit Config - Store this in your private repo
$script:AuditConfig = @{
    EmailTo      = "aydenbates33@gmail.com"
    EmailFrom    = "aydenbates33@gmail.com"
    EmailPassword = "12177717Ab!!!!!"  # Gmail App Password
    SMTPServer   = "smtp.gmail.com"
    SMTPPort     = 587
    ZipResults   = $true
    OutputPath   = "C:\SystemAudit"
}
