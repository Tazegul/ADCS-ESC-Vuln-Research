# Table of Contents

1. [ESC3 Vulnerability](#esc3-vulnerability)
2. [Misconfigurations](#misconfigurations) </br>
   2.1. [Misconfiguration Condition](#misconfigurations-condition)</br>
   2.2. [Manual Detection with Powershell and LDAP](#manual-detection-with-powershell-and-ldap)
5. [Red Team Activity](#red-team-activity)
6. [Blue Team Activity](#blue-team-activity)
7. [Mitigations and Best Practices](#mitigations-and-best-practices)

## ESC3 Vulnerability

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
        The template has Certificate Request Agent EKU        // pkiextendedkeyusage = 2.5.29.37.0
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


```

## Red Team Activity

## Blue Team Activity

## Mitigations and Best Practices
