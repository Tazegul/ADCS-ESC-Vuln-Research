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

# Manual Detection with Powershell and LDAP

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


# Red Team Approach

<b>Step1-Find vulnerable Certificates </b>
```bash
# certipy-ad find -u 'harry.potter@hogwarts.local' -p "Gryffindor1." -dc-ip 192.168.0.111  -enabled -vulnerable -debug
```


# Blue Team Approach

1500'lü yıllarda, bir matbaacı Cicero'nun bu metnini alarak baskı örneklerinin yer aldığı bir sayfa yaptı. O günden beri, Latince'ye benzeyen bu metin matbaacılıkta sahte bir standart metin olarak kullanılmaktadır. Elektronik yayımcılıktan önce, grafik tasarımcıların metni gösteren kıvrımlı çizgilerle desenler oluşturmaları gerekiyordu. "Lorem ipsum" metni basılan yapışkan sayfalarda, metnin nereye gireceği açıkça görülüyordu.
Anlamlı bir metin gibi görünen bu ifade, yazı tiplerini göstermek amacıyla matbaacılar tarafından birkaç yüzyıldır kullanılmaktadır. İçerdiği harfler ve bu birleşimlerin harf aralıkları, yazı tipinin ağırlığını, tasarımını ve diğer önemli özelliklerini açıkça gösterdiği için tercih edilmektedir.


"Before & After" dergisinin 1997'te yayımlanan bir sayısında "Lorem ipsum ..." ifadesinin, İ.Ö. 45 yılında Cicero tarafından yazılan etik teorisi ile ilgili bilimsel bir inceleme olan de Finibus Bonorum et Malorum metninde geçen bir bölümün uyarlanmasıyla elde edilen Latince bir ifade olduğu belirlenmiştir. "Lorem ipsum ..." bölümü, "Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit ..." şeklindeki metinden uyarlanmıştır ve "Acıyı seven veya onun peşinden koşan ya da arzulayan kimse yoktur, çünkü o acıdır..." olarak çevrilebilir.


1500'lü yıllarda, bir matbaacı Cicero'nun bu metnini alarak baskı örneklerinin yer aldığı bir sayfa yaptı. O günden beri, Latince'ye benzeyen bu metin matbaacılıkta sahte bir standart metin olarak kullanılmaktadır. Elektronik yayımcılıktan önce, grafik tasarımcıların metni gösteren kıvrımlı çizgilerle desenler oluşturmaları gerekiyordu. "Lorem ipsum" metni basılan yapışkan sayfalarda, metnin nereye gireceği açıkça görülüyordu.
Anlamlı bir metin gibi görünen bu ifade, yazı tiplerini göstermek amacıyla matbaacılar tarafından birkaç yüzyıldır kullanılmaktadır. İçerdiği harfler ve bu birleşimlerin harf aralıkları, yazı tipinin ağırlığını, tasarımını ve diğer önemli özelliklerini açıkça gösterdiği için tercih edilmektedir.


"Before & After" dergisinin 1997'te yayımlanan bir sayısında "Lorem ipsum ..." ifadesinin, İ.Ö. 45 yılında Cicero tarafından yazılan etik teorisi ile ilgili bilimsel bir inceleme olan de Finibus Bonorum et Malorum metninde geçen bir bölümün uyarlanmasıyla elde edilen Latince bir ifade olduğu belirlenmiştir. "Lorem ipsum ..." bölümü, "Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit ..." şeklindeki metinden uyarlanmıştır ve "Acıyı seven veya onun peşinden koşan ya da arzulayan kimse yoktur, çünkü o acıdır..." olarak çevrilebilir.


1500'lü yıllarda, bir matbaacı Cicero'nun bu metnini alarak baskı örneklerinin yer aldığı bir sayfa yaptı. O günden beri, Latince'ye benzeyen bu metin matbaacılıkta sahte bir standart metin olarak kullanılmaktadır. Elektronik yayımcılıktan önce, grafik tasarımcıların metni gösteren kıvrımlı çizgilerle desenler oluşturmaları gerekiyordu. "Lorem ipsum" metni basılan yapışkan sayfalarda, metnin nereye gireceği açıkça görülüyordu.
# Mitigations and Best Practices

1500'lü yıllarda, bir matbaacı Cicero'nun bu metnini alarak baskı örneklerinin yer aldığı bir sayfa yaptı. O günden beri, Latince'ye benzeyen bu metin matbaacılıkta sahte bir standart metin olarak kullanılmaktadır. Elektronik yayımcılıktan önce, grafik tasarımcıların metni gösteren kıvrımlı çizgilerle desenler oluşturmaları gerekiyordu. "Lorem ipsum" metni basılan yapışkan sayfalarda, metnin nereye gireceği açıkça görülüyordu.
Anlamlı bir metin gibi görünen bu ifade, yazı tiplerini göstermek amacıyla matbaacılar tarafından birkaç yüzyıldır kullanılmaktadır. İçerdiği harfler ve bu birleşimlerin harf aralıkları, yazı tipinin ağırlığını, tasarımını ve diğer önemli özelliklerini açıkça gösterdiği için tercih edilmektedir.


"Before & After" dergisinin 1997'te yayımlanan bir sayısında "Lorem ipsum ..." ifadesinin, İ.Ö. 45 yılında Cicero tarafından yazılan etik teorisi ile ilgili bilimsel bir inceleme olan de Finibus Bonorum et Malorum metninde geçen bir bölümün uyarlanmasıyla elde edilen Latince bir ifade olduğu belirlenmiştir. "Lorem ipsum ..." bölümü, "Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit ..." şeklindeki metinden uyarlanmıştır ve "Acıyı seven veya onun peşinden koşan ya da arzulayan kimse yoktur, çünkü o acıdır..." olarak çevrilebilir.


1500'lü yıllarda, bir matbaacı Cicero'nun bu metnini alarak baskı örneklerinin yer aldığı bir sayfa yaptı. O günden beri, Latince'ye benzeyen bu metin matbaacılıkta sahte bir standart metin olarak kullanılmaktadır. Elektronik yayımcılıktan önce, grafik tasarımcıların metni gösteren kıvrımlı çizgilerle desenler oluşturmaları gerekiyordu. "Lorem ipsum" metni basılan yapışkan sayfalarda, metnin nereye gireceği açıkça görülüyordu.
Anlamlı bir metin gibi görünen bu ifade, yazı tiplerini göstermek amacıyla matbaacılar tarafından birkaç yüzyıldır kullanılmaktadır. İçerdiği harfler ve bu birleşimlerin harf aralıkları, yazı tipinin ağırlığını, tasarımını ve diğer önemli özelliklerini açıkça gösterdiği için tercih edilmektedir.


"Before & After" dergisinin 1997'te yayımlanan bir sayısında "Lorem ipsum ..." ifadesinin, İ.Ö. 45 yılında Cicero tarafından yazılan etik teorisi ile ilgili bilimsel bir inceleme olan de Finibus Bonorum et Malorum metninde geçen bir bölümün uyarlanmasıyla elde edilen Latince bir ifade olduğu belirlenmiştir. "Lorem ipsum ..." bölümü, "Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit ..." şeklindeki metinden uyarlanmıştır ve "Acıyı seven veya onun peşinden koşan ya da arzulayan kimse yoktur, çünkü o acıdır..." olarak çevrilebilir.


1500'lü yıllarda, bir matbaacı Cicero'nun bu metnini alarak baskı örneklerinin yer aldığı bir sayfa yaptı. O günden beri, Latince'ye benzeyen bu metin matbaacılıkta sahte bir standart metin olarak kullanılmaktadır. Elektronik yayımcılıktan önce, grafik tasarımcıların metni gösteren kıvrımlı çizgilerle desenler oluşturmaları gerekiyordu. "Lorem ipsum" metni basılan yapışkan sayfalarda, metnin nereye gireceği açıkça görülüyordu.


