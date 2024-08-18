# Table of Contents

1. [ESC1 Vulnerability](#esc1-vulnerability)
1. [Misconfigurations](#misconfigurations)
2. [Manual Detection](#manual-detection)
3. [Red Team Approach](#red-team-approach)
4. [Blue Team Approach](#blue-team-approach)
5. [Mitigations and Best Practices](#mitigations-and-best-practices)




## ESC1 Vulnerability
The ESC1 vulnerability, also known as the "ESC1" or "Enterprise Certificate Services Vulnerability," is a security flaw in certain certificate templates used in Microsoft Active Directory Certificate Services (AD CS). This vulnerability allows users with low privileges to request and obtain certificates on behalf of any domain object, including high-privilege accounts like domain administrators.

## Misconfigurations
<img src="https://github.com/user-attachments/assets/d6aea50f-6f63-400e-8612-e2e95194decd" width="300" height="500">
<img src="https://github.com/user-attachments/assets/79d1ae3a-1d04-4499-9016-11aecdafaa11" width="300" height="500"> <br>
<img src="https://github.com/user-attachments/assets/b1db857d-8f4d-4798-9866-96a4491039ef" width="300" height="500">
<img src="https://github.com/user-attachments/assets/1f1eab61-508b-4c3d-a891-2fd3fcbcac25" width="300" height="500"> <br>

### Misconfigurations Condition
```
IF 
(
    Requester has the ability to specify subjectAltName (SAN) in the CSR
    <pre style="background-color: #f4f4f4; color: #333;">
    // (Suplly in Request)
    </pre>
    AND 
    (NOT (msPKI-Enrollment-Flag has the 0x2 bit set))  // The msPKI-Enrollment-Flag must NOT have the 0x2 bit set
    AND 
    (
        (msPKI-RA-Signature = 0)  // The msPKI-RA-Signature must be 0
        OR 
        (msPKI-RA-Signature attribute is NOT present)  // The msPKI-RA-Signature attribute must NOT be set (i.e., it doesn't exist)
    )
    AND 
    (
        (pkiextendedkeyusage = 1.3.6.1.4.1.311.20.2.2)  // The template has Smartcard Logon EKU
        OR 
        (pkiextendedkeyusage = 1.3.6.1.5.5.7.3.2)  // The template has Client Authentication EKU
        OR 
        (pkiextendedkeyusage = 1.3.6.1.5.2.3.4)  // The template has PKINIT Client Authentication EKU
    )
    AND 
    (msPKI-Certificate-Name-Flag has the 0x1 bit set)  // The msPKI-Certificate-Name-Flag must have the 0x1 bit set
)
```


"Before & After" dergisinin 1997'te yayımlanan bir sayısında "Lorem ipsum ..." ifadesinin, İ.Ö. 45 yılında Cicero tarafından yazılan etik teorisi ile ilgili bilimsel bir inceleme olan de Finibus Bonorum et Malorum metninde geçen bir bölümün uyarlanmasıyla elde edilen Latince bir ifade olduğu belirlenmiştir. "Lorem ipsum ..." bölümü, "Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit ..." şeklindeki metinden uyarlanmıştır ve "Acıyı seven veya onun peşinden koşan ya da arzulayan kimse yoktur, çünkü o acıdır..." olarak çevrilebilir.


1500'lü yıllarda, bir matbaacı Cicero'nun bu metnini alarak baskı örneklerinin yer aldığı bir sayfa yaptı. O günden beri, Latince'ye benzeyen bu metin matbaacılıkta sahte bir standart metin olarak kullanılmaktadır. Elektronik yayımcılıktan önce, grafik tasarımcıların metni gösteren kıvrımlı çizgilerle desenler oluşturmaları gerekiyordu. "Lorem ipsum" metni basılan yapışkan sayfalarda, metnin nereye gireceği açıkça görülüyordu.
Anlamlı bir metin gibi görünen bu ifade, yazı tiplerini göstermek amacıyla matbaacılar tarafından birkaç yüzyıldır kullanılmaktadır. İçerdiği harfler ve bu birleşimlerin harf aralıkları, yazı tipinin ağırlığını, tasarımını ve diğer önemli özelliklerini açıkça gösterdiği için tercih edilmektedir.


"Before & After" dergisinin 1997'te yayımlanan bir sayısında "Lorem ipsum ..." ifadesinin, İ.Ö. 45 yılında Cicero tarafından yazılan etik teorisi ile ilgili bilimsel bir inceleme olan de Finibus Bonorum et Malorum metninde geçen bir bölümün uyarlanmasıyla elde edilen Latince bir ifade olduğu belirlenmiştir. "Lorem ipsum ..." bölümü, "Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit ..." şeklindeki metinden uyarlanmıştır ve "Acıyı seven veya onun peşinden koşan ya da arzulayan kimse yoktur, çünkü o acıdır..." olarak çevrilebilir.


1500'lü yıllarda, bir matbaacı Cicero'nun bu metnini alarak baskı örneklerinin yer aldığı bir sayfa yaptı. O günden beri, Latince'ye benzeyen bu metin matbaacılıkta sahte bir standart metin olarak kullanılmaktadır. Elektronik yayımcılıktan önce, grafik tasarımcıların metni gösteren kıvrımlı çizgilerle desenler oluşturmaları gerekiyordu. "Lorem ipsum" metni basılan yapışkan sayfalarda, metnin nereye gireceği açıkça görülüyordu.
Anlamlı bir metin gibi görünen bu ifade, yazı tiplerini göstermek amacıyla matbaacılar tarafından birkaç yüzyıldır kullanılmaktadır. İçerdiği harfler ve bu birleşimlerin harf aralıkları, yazı tipinin ağırlığını, tasarımını ve diğer önemli özelliklerini açıkça gösterdiği için tercih edilmektedir.


"Before & After" dergisinin 1997'te yayımlanan bir sayısında "Lorem ipsum ..." ifadesinin, İ.Ö. 45 yılında Cicero tarafından yazılan etik teorisi ile ilgili bilimsel bir inceleme olan de Finibus Bonorum et Malorum metninde geçen bir bölümün uyarlanmasıyla elde edilen Latince bir ifade olduğu belirlenmiştir. "Lorem ipsum ..." bölümü, "Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit ..." şeklindeki metinden uyarlanmıştır ve "Acıyı seven veya onun peşinden koşan ya da arzulayan kimse yoktur, çünkü o acıdır..." olarak çevrilebilir.


1500'lü yıllarda, bir matbaacı Cicero'nun bu metnini alarak baskı örneklerinin yer aldığı bir sayfa yaptı. O günden beri, Latince'ye benzeyen bu metin matbaacılıkta sahte bir standart metin olarak kullanılmaktadır. Elektronik yayımcılıktan önce, grafik tasarımcıların metni gösteren kıvrımlı çizgilerle desenler oluşturmaları gerekiyordu. "Lorem ipsum" metni basılan yapışkan sayfalarda, metnin nereye gireceği açıkça görülüyordu.
Anlamlı bir metin gibi görünen bu ifade, yazı tiplerini göstermek amacıyla matbaacılar tarafından birkaç yüzyıldır kullanılmaktadır. İçerdiği harfler ve bu birleşimlerin harf aralıkları, yazı tipinin ağırlığını, tasarımını ve diğer önemli özelliklerini açıkça gösterdiği için tercih edilmektedir.


"Before & After" dergisinin 1997'te yayımlanan bir sayısında "Lorem ipsum ..." ifadesinin, İ.Ö. 45 yılında Cicero tarafından yazılan etik teorisi ile ilgili bilimsel bir inceleme olan de Finibus Bonorum et Malorum metninde geçen bir bölümün uyarlanmasıyla elde edilen Latince bir ifade olduğu belirlenmiştir. "Lorem ipsum ..." bölümü, "Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit ..." şeklindeki metinden uyarlanmıştır ve "Acıyı seven veya onun peşinden koşan ya da arzulayan kimse yoktur, çünkü o acıdır..." olarak çevrilebilir.


1500'lü yıllarda, bir matbaacı Cicero'nun bu metnini alarak baskı örneklerinin yer aldığı bir sayfa yaptı. O günden beri, Latince'ye benzeyen bu metin matbaacılıkta sahte bir standart metin olarak kullanılmaktadır. Elektronik yayımcılıktan önce, grafik tasarımcıların metni gösteren kıvrımlı çizgilerle desenler oluşturmaları gerekiyordu. "Lorem ipsum" metni basılan yapışkan sayfalarda, metnin nereye gireceği açıkça görülüyordu.
# Manual Detection

Anlamlı bir metin gibi görünen bu ifade, yazı tiplerini göstermek amacıyla matbaacılar tarafından birkaç yüzyıldır kullanılmaktadır. İçerdiği harfler ve bu birleşimlerin harf aralıkları, yazı tipinin ağırlığını, tasarımını ve diğer önemli özelliklerini açıkça gösterdiği için tercih edilmektedir.


"Before & After" dergisinin 1997'te yayımlanan bir sayısında "Lorem ipsum ..." ifadesinin, İ.Ö. 45 yılında Cicero tarafından yazılan etik teorisi ile ilgili bilimsel bir inceleme olan de Finibus Bonorum et Malorum metninde geçen bir bölümün uyarlanmasıyla elde edilen Latince bir ifade olduğu belirlenmiştir. "Lorem ipsum ..." bölümü, "Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit ..." şeklindeki metinden uyarlanmıştır ve "Acıyı seven veya onun peşinden koşan ya da arzulayan kimse yoktur, çünkü o acıdır..." olarak çevrilebilir.


1500'lü yıllarda, bir matbaacı Cicero'nun bu metnini alarak baskı örneklerinin yer aldığı bir sayfa yaptı. O günden beri, Latince'ye benzeyen bu metin matbaacılıkta sahte bir standart metin olarak kullanılmaktadır. Elektronik yayımcılıktan önce, grafik tasarımcıların metni gösteren kıvrımlı çizgilerle desenler oluşturmaları gerekiyordu. "Lorem ipsum" metni basılan yapışkan sayfalarda, metnin nereye gireceği açıkça görülüyordu.
Anlamlı bir metin gibi görünen bu ifade, yazı tiplerini göstermek amacıyla matbaacılar tarafından birkaç yüzyıldır kullanılmaktadır. İçerdiği harfler ve bu birleşimlerin harf aralıkları, yazı tipinin ağırlığını, tasarımını ve diğer önemli özelliklerini açıkça gösterdiği için tercih edilmektedir.


"Before & After" dergisinin 1997'te yayımlanan bir sayısında "Lorem ipsum ..." ifadesinin, İ.Ö. 45 yılında Cicero tarafından yazılan etik teorisi ile ilgili bilimsel bir inceleme olan de Finibus Bonorum et Malorum metninde geçen bir bölümün uyarlanmasıyla elde edilen Latince bir ifade olduğu belirlenmiştir. "Lorem ipsum ..." bölümü, "Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit ..." şeklindeki metinden uyarlanmıştır ve "Acıyı seven veya onun peşinden koşan ya da arzulayan kimse yoktur, çünkü o acıdır..." olarak çevrilebilir.


1500'lü yıllarda, bir matbaacı Cicero'nun bu metnini alarak baskı örneklerinin yer aldığı bir sayfa yaptı. O günden beri, Latince'ye benzeyen bu metin matbaacılıkta sahte bir standart metin olarak kullanılmaktadır. Elektronik yayımcılıktan önce, grafik tasarımcıların metni gösteren kıvrımlı çizgilerle desenler oluşturmaları gerekiyordu. "Lorem ipsum" metni basılan yapışkan sayfalarda, metnin nereye gireceği açıkça görülüyordu.
Anlamlı bir metin gibi görünen bu ifade, yazı tiplerini göstermek amacıyla matbaacılar tarafından birkaç yüzyıldır kullanılmaktadır. İçerdiği harfler ve bu birleşimlerin harf aralıkları, yazı tipinin ağırlığını, tasarımını ve diğer önemli özelliklerini açıkça gösterdiği için tercih edilmektedir.


"Before & After" dergisinin 1997'te yayımlanan bir sayısında "Lorem ipsum ..." ifadesinin, İ.Ö. 45 yılında Cicero tarafından yazılan etik teorisi ile ilgili bilimsel bir inceleme olan de Finibus Bonorum et Malorum metninde geçen bir bölümün uyarlanmasıyla elde edilen Latince bir ifade olduğu belirlenmiştir. "Lorem ipsum ..." bölümü, "Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit ..." şeklindeki metinden uyarlanmıştır ve "Acıyı seven veya onun peşinden koşan ya da arzulayan kimse yoktur, çünkü o acıdır..." olarak çevrilebilir.


1500'lü yıllarda, bir matbaacı Cicero'nun bu metnini alarak baskı örneklerinin yer aldığı bir sayfa yaptı. O günden beri, Latince'ye benzeyen bu metin matbaacılıkta sahte bir standart metin olarak kullanılmaktadır. Elektronik yayımcılıktan önce, grafik tasarımcıların metni gösteren kıvrımlı çizgilerle desenler oluşturmaları gerekiyordu. "Lorem ipsum" metni basılan yapışkan sayfalarda, metnin nereye gireceği açıkça görülüyordu.
Anlamlı bir metin gibi görünen bu ifade, yazı tiplerini göstermek amacıyla matbaacılar tarafından birkaç yüzyıldır kullanılmaktadır. İçerdiği harfler ve bu birleşimlerin harf aralıkları, yazı tipinin ağırlığını, tasarımını ve diğer önemli özelliklerini açıkça gösterdiği için tercih edilmektedir.


"Before & After" dergisinin 1997'te yayımlanan bir sayısında "Lorem ipsum ..." ifadesinin, İ.Ö. 45 yılında Cicero tarafından yazılan etik teorisi ile ilgili bilimsel bir inceleme olan de Finibus Bonorum et Malorum metninde geçen bir bölümün uyarlanmasıyla elde edilen Latince bir ifade olduğu belirlenmiştir. "Lorem ipsum ..." bölümü, "Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit ..." şeklindeki metinden uyarlanmıştır ve "Acıyı seven veya onun peşinden koşan ya da arzulayan kimse yoktur, çünkü o acıdır..." olarak çevrilebilir.


1500'lü yıllarda, bir matbaacı Cicero'nun bu metnini alarak baskı örneklerinin yer aldığı bir sayfa yaptı. O günden beri, Latince'ye benzeyen bu metin matbaacılıkta sahte bir standart metin olarak kullanılmaktadır. Elektronik yayımcılıktan önce, grafik tasarımcıların metni gösteren kıvrımlı çizgilerle desenler oluşturmaları gerekiyordu. "Lorem ipsum" metni basılan yapışkan sayfalarda, metnin nereye gireceği açıkça görülüyordu.

# Red Team Approach
1500'lü yıllarda, bir matbaacı Cicero'nun bu metnini alarak baskı örneklerinin yer aldığı bir sayfa yaptı. O günden beri, Latince'ye benzeyen bu metin matbaacılıkta sahte bir standart metin olarak kullanılmaktadır. Elektronik yayımcılıktan önce, grafik tasarımcıların metni gösteren kıvrımlı çizgilerle desenler oluşturmaları gerekiyordu. "Lorem ipsum" metni basılan yapışkan sayfalarda, metnin nereye gireceği açıkça görülüyordu.
Anlamlı bir metin gibi görünen bu ifade, yazı tiplerini göstermek amacıyla matbaacılar tarafından birkaç yüzyıldır kullanılmaktadır. İçerdiği harfler ve bu birleşimlerin harf aralıkları, yazı tipinin ağırlığını, tasarımını ve diğer önemli özelliklerini açıkça gösterdiği için tercih edilmektedir.


"Before & After" dergisinin 1997'te yayımlanan bir sayısında "Lorem ipsum ..." ifadesinin, İ.Ö. 45 yılında Cicero tarafından yazılan etik teorisi ile ilgili bilimsel bir inceleme olan de Finibus Bonorum et Malorum metninde geçen bir bölümün uyarlanmasıyla elde edilen Latince bir ifade olduğu belirlenmiştir. "Lorem ipsum ..." bölümü, "Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit ..." şeklindeki metinden uyarlanmıştır ve "Acıyı seven veya onun peşinden koşan ya da arzulayan kimse yoktur, çünkü o acıdır..." olarak çevrilebilir.


1500'lü yıllarda, bir matbaacı Cicero'nun bu metnini alarak baskı örneklerinin yer aldığı bir sayfa yaptı. O günden beri, Latince'ye benzeyen bu metin matbaacılıkta sahte bir standart metin olarak kullanılmaktadır. Elektronik yayımcılıktan önce, grafik tasarımcıların metni gösteren kıvrımlı çizgilerle desenler oluşturmaları gerekiyordu. "Lorem ipsum" metni basılan yapışkan sayfalarda, metnin nereye gireceği açıkça görülüyordu.
Anlamlı bir metin gibi görünen bu ifade, yazı tiplerini göstermek amacıyla matbaacılar tarafından birkaç yüzyıldır kullanılmaktadır. İçerdiği harfler ve bu birleşimlerin harf aralıkları, yazı tipinin ağırlığını, tasarımını ve diğer önemli özelliklerini açıkça gösterdiği için tercih edilmektedir.


"Before & After" dergisinin 1997'te yayımlanan bir sayısında "Lorem ipsum ..." ifadesinin, İ.Ö. 45 yılında Cicero tarafından yazılan etik teorisi ile ilgili bilimsel bir inceleme olan de Finibus Bonorum et Malorum metninde geçen bir bölümün uyarlanmasıyla elde edilen Latince bir ifade olduğu belirlenmiştir. "Lorem ipsum ..." bölümü, "Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit ..." şeklindeki metinden uyarlanmıştır ve "Acıyı seven veya onun peşinden koşan ya da arzulayan kimse yoktur, çünkü o acıdır..." olarak çevrilebilir.


1500'lü yıllarda, bir matbaacı Cicero'nun bu metnini alarak baskı örneklerinin yer aldığı bir sayfa yaptı. O günden beri, Latince'ye benzeyen bu metin matbaacılıkta sahte bir standart metin olarak kullanılmaktadır. Elektronik yayımcılıktan önce, grafik tasarımcıların metni gösteren kıvrımlı çizgilerle desenler oluşturmaları gerekiyordu. "Lorem ipsum" metni basılan yapışkan sayfalarda, metnin nereye gireceği açıkça görülüyordu.

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


