
# SOC Windows Event Log Analyzer

Windows işletim sistemindeki Security olay günlüklerini analiz ederek başarısız oturum açma girişimlerini inceleyen ve şüpheli aktiviteleri tespit etmeyi amaçlayan Python tabanlı bir SOC (Security Operations Center) projesidir.

## Projenin Amacı

Bu projenin amacı, Windows güvenlik günlüklerini inceleyerek başarısız oturum açma girişimlerini analiz etmek ve belirli bir zaman aralığında yoğunlaşan başarısız girişleri tespit etmektir.

Özellikle brute-force (kaba kuvvet) saldırılarına benzeyen giriş denemelerinin belirlenmesi hedeflenmektedir.

## Özellikler

- Windows Security olay günlüklerini okuma
- Event ID 4625 üzerinden başarısız oturum açma kayıtlarını toplama
- Olay kayıtlarından kullanıcı adı, kaynak IP, tarih, bilgisayar adı ve oturum açma türü gibi bilgileri çıkarma
- Kaynak IP adreslerine göre başarısız giriş sayılarını analiz etme
- 60 saniye içerisinde aynı IP adresinden 10 veya daha fazla başarısız giriş gerçekleştiğinde şüpheli aktivite uyarısı oluşturma
- Analiz sonuçlarını CSV formatında dışa aktarma
- Brute-force tespit fonksiyonunu otomatik testlerle kontrol etme

## Kullanılan Teknolojiler

- Python
- pywin32
- XML
- CSV
- unittest

## Proje Yapısı

```text
soc-windows-event-log-analyzer/
│
├── data/
├── reports/
├── src/
│   └── main.py
├── tests/
│   └── test_analyzer.py
├── .gitignore
├── README.md
└── requirements.txt
```

## Kurulum

1. Projeyi GitHub üzerinden bilgisayarınıza indirin:

```bash
git clone https://github.com/melike-lab/soc-windows-event-log-analyzer.git
```

2. Proje klasörüne geçin:

```bash
cd soc-windows-event-log-analyzer
```

3. Sanal ortam oluşturun:

```bash
python -m venv .venv
```

4. Gerekli kütüphaneleri yükleyin:

```bash
pip install -r requirements.txt
```

## Çalıştırma

Windows Security olay günlüklerini okuyabilmek için terminali veya VS Code'u yönetici olarak çalıştırmanız gerekir.

Proje ana klasöründeyken aşağıdaki komutu çalıştırın:

```bash
python src/main.py
```

Program, son 1000 başarısız oturum açma olayını inceleyerek analiz sonuçlarını terminalde gösterir.

Oluşturulan CSV raporları `reports/` klasörüne kaydedilir.

## Brute-Force Tespit Mantığı

Proje, aynı kaynak IP adresinden gelen başarısız oturum açma girişimlerini zaman bilgilerine göre inceler.

Belirlenen eşik:

- Zaman aralığı: 60 saniye
- Başarısız giriş sayısı: 10 veya daha fazla

Bu koşul sağlandığında şüpheli aktivite uyarısı oluşturulur.

**Not:** Bu eşik, şüpheli davranışları belirlemek için kullanılan basit bir analiz kuralıdır. Tek başına brute-force saldırısının kesin kanıtı değildir.

## Testler

Projedeki brute-force tespit fonksiyonunu kontrol etmek için Python unittest modülü kullanılmıştır.

Testleri çalıştırmak için:

```bash
python -m unittest discover -s tests -v
```

Testler şu durumları kontrol eder:

- 60 saniye içerisinde 10 başarısız giriş olduğunda tespit yapılması
- 60 saniye içerisinde 9 başarısız giriş olduğunda uyarı oluşturulmaması
- Kaynak IP bilgisi olmayan kayıtların analiz dışında bırakılması

## Güvenlik ve Gizlilik

Bu proje Windows olay günlüklerini yalnızca okumak ve analiz etmek amacıyla geliştirilmiştir. Sistem günlüklerinde değişiklik yapmaz veya kayıtları silmez.

Gerçek sistemlere ait kullanıcı adları, IP adresleri ve diğer hassas olay kayıtları herkese açık GitHub depolarına yüklenmemelidir.

## Geliştirme Durumu

Proje geliştirme aşamasındadır. İlerleyen aşamalarda başarılı oturum açma kayıtlarının analizi, farklı olay türlerinin incelenmesi ve raporlama özelliklerinin geliştirilmesi hedeflenmektedir.