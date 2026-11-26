
import win32evtlog
import xml.etree.ElementTree as ET
import csv

from pathlib import Path
from datetime import datetime, timedelta


def read_failed_logins():
    log_name = "Security"
    query_handle = None
    failed_logins = []

    # En fazla 1000 başarısız oturum açma olayını sorgula
    query = "*[System[(EventID=4625)]]"

    try:
        query_handle = win32evtlog.EvtQuery(
            log_name,
            win32evtlog.EvtQueryChannelPath
            | win32evtlog.EvtQueryReverseDirection,
            query
        )

        print("Windows Security logları sorgulanıyor...")
        print("=" * 60)

        events = win32evtlog.EvtNext(query_handle, 1000)

        if not events:
            print("Başarısız oturum açma kaydı bulunamadı.")
            return failed_logins

        for event in events:
            xml_data = win32evtlog.EvtRender(
                event,
                win32evtlog.EvtRenderEventXml
            )

            root = ET.fromstring(xml_data)

            namespace = {
                "ns": "http://schemas.microsoft.com/win/2004/08/events/event"
            }

            event_data = {}

            for item in root.findall(
                ".//ns:EventData/ns:Data",
                namespace
            ):
                field_name = item.attrib.get("Name")
                field_value = item.text or ""

                if field_name:
                    event_data[field_name] = field_value

            system_time = root.find(
                ".//ns:System/ns:TimeCreated",
                namespace
            )

            computer = root.find(
                ".//ns:System/ns:Computer",
                namespace
            )

            if system_time is None:
                continue

            # Olay bilgilerini listeye ekle
            failed_logins.append({
                "time": system_time.attrib.get("SystemTime"),
                "computer": computer.text if computer is not None else "Bilinmiyor",
                "username": event_data.get("TargetUserName"),
                "domain": event_data.get("TargetDomainName"),
                "source_ip": event_data.get("IpAddress"),
                "logon_type": event_data.get("LogonType"),
                "status": event_data.get("Status"),
                "sub_status": event_data.get("SubStatus"),
                "process_name": event_data.get("ProcessName")
            })

            print("\nBAŞARISIZ OTURUM AÇMA TESPİT EDİLDİ")
            print("-" * 60)

            print(f"Tarih: {system_time.attrib.get('SystemTime')}")
            print(f"Bilgisayar: {computer.text if computer is not None else 'Bilinmiyor'}")
            print(f"Kullanıcı: {event_data.get('TargetUserName', 'Bilinmiyor')}")
            print(f"Hedef Domain: {event_data.get('TargetDomainName', 'Bilinmiyor')}")
            print(f"Kaynak IP: {event_data.get('IpAddress', 'Bilinmiyor')}")
            print(f"Logon Type: {event_data.get('LogonType', 'Bilinmiyor')}")
            print(f"Status: {event_data.get('Status', 'Bilinmiyor')}")
            print(f"SubStatus: {event_data.get('SubStatus', 'Bilinmiyor')}")
            print(f"Process Name: {event_data.get('ProcessName', 'Bilinmiyor')}")

            print("-" * 60)

        return failed_logins

    except Exception as error:
        print("Olay kayıtları okunurken hata oluştu:")
        print(error)
        return failed_logins


def analyze_failed_logins(failed_logins):
    ip_attempts = {}

    for login in failed_logins:
        source_ip = login.get("source_ip")

        # IP adresi bulunmuyorsa kaydı atla
        if not source_ip or source_ip == "-":
            continue

        # Yeni IP adresi için sayaç oluştur
        if source_ip not in ip_attempts:
            ip_attempts[source_ip] = 0

        ip_attempts[source_ip] += 1

    print("\nIP ADRESİNE GÖRE BAŞARISIZ GİRİŞ ANALİZİ")
    print("=" * 60)

    if not ip_attempts:
        print("Analiz edilebilecek kaynak IP adresi bulunamadı.")
        return

    for ip, count in ip_attempts.items():
        print(f"Kaynak IP: {ip}")
        print(f"Başarısız giriş sayısı: {count}")
        print("-" * 60)


def detect_brute_force(failed_logins):
    ip_attempts = {}

    for login in failed_logins:
        source_ip = login.get("source_ip")
        event_time = login.get("time")

        # IP veya zaman bilgisi yoksa kaydı atla
        if not source_ip or source_ip == "-" or not event_time:
            continue

        try:
            event_time = datetime.fromisoformat(
                event_time.replace("Z", "+00:00")
            )
        except ValueError:
            continue

        if source_ip not in ip_attempts:
            ip_attempts[source_ip] = []

        ip_attempts[source_ip].append({
            "time": event_time,
            "username": login.get("username")
        })

    print("\nBRUTE FORCE ŞÜPHELİ AKTİVİTE ANALİZİ")
    print("=" * 60)

    suspicious_found = False

    for ip, attempts in ip_attempts.items():

        # Girişleri zamana göre sırala
        attempts.sort(key=lambda x: x["time"])

        # Her giriş zamanını başlangıç kabul ederek 60 saniyeyi incele
        for i in range(len(attempts)):
            start_time = attempts[i]["time"]
            window_attempts = []

            for j in range(i, len(attempts)):
                current_time = attempts[j]["time"]

                if current_time - start_time <= timedelta(seconds=60):
                    window_attempts.append(attempts[j])
                else:
                    break

            # 60 saniye içinde 10 veya daha fazla giriş varsa
            if len(window_attempts) >= 10:
                suspicious_found = True

                usernames = sorted({
                    attempt["username"]
                    for attempt in window_attempts
                    if attempt["username"]
                })

                end_time = window_attempts[-1]["time"]

                print("\nŞÜPHELİ AKTİVİTE TESPİT EDİLDİ")
                print("-" * 60)
                print(f"Kaynak IP: {ip}")
                print(
                    f"Hedef Kullanıcı: "
                    f"{', '.join(usernames) if usernames else 'Bilinmiyor'}"
                )
                print(f"Başarısız Giriş Sayısı: {len(window_attempts)}")
                print("Zaman Aralığı: 60 saniye")
                print(f"İlk Giriş: {start_time}")
                print(f"Son Giriş: {end_time}")
                print("Önem Derecesi: HIGH")
                print(
                    "Açıklama: Kısa süre içerisinde çok sayıda "
                    "başarısız oturum açma girişimi."
                )
                print("-" * 60)

                break

    if not suspicious_found:
        print("Belirlenen eşik değere ulaşan şüpheli aktivite bulunamadı.")

def export_to_csv(failed_logins):
    # Projenin ana klasörünü belirle
    project_dir = Path(__file__).resolve().parent.parent

    # reports klasörünü oluştur
    reports_dir = project_dir / "reports"
    reports_dir.mkdir(exist_ok=True)

    # Rapor dosyasına tarih ve saat ekle
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    report_file = reports_dir / f"failed_logins_{timestamp}.csv"

    # CSV dosyasına yazılacak sütunlar
    fieldnames = [
        "time",
        "computer",
        "username",
        "domain",
        "source_ip",
        "logon_type",
        "status",
        "sub_status",
        "process_name"
    ]

    try:
        with open(
            report_file,
            mode="w",
            newline="",
            encoding="utf-8-sig"
        ) as csv_file:

            writer = csv.DictWriter(
                csv_file,
                fieldnames=fieldnames
            )

            writer.writeheader()
            writer.writerows(failed_logins)

        print("\nCSV RAPORU OLUŞTURULDU")
        print("=" * 60)
        print(f"Rapor konumu: {report_file}")
        print(f"Raporlanan kayıt sayısı: {len(failed_logins)}")

    except OSError as error:
        print("CSV raporu oluşturulurken hata oluştu:")
        print(error)


def main():
    print("SOC Windows Event Log Analyzer")
    print("=" * 60)

    failed_logins = read_failed_logins()

    print("\nTOPLAM ANALİZ SONUCU")
    print("=" * 60)
    print(f"Toplanan başarısız giriş sayısı: {len(failed_logins)}")

    analyze_failed_logins(failed_logins)

    detect_brute_force(failed_logins)

    export_to_csv(failed_logins)


if __name__ == "__main__":
    main()
