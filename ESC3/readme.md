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

### Step2-Request a Certificate on Behalf of Other Another User

## Blue Team Activity

## Mitigations and Best Practices
