from utils.cli import parse_args

from analyzer.reader import read_logs
from analyzer.detector import detect_suspicious
from analyzer.aggregator import score_events
from analyzer.reporter import write_report

from security.blacklist import write_blacklist
from security.firewall import export_iptables, export_ufw


def main():
    # 1️⃣ CLI argümanlarını al
    args = parse_args()

    # 2️⃣ Logları oku / parse et
    logs = read_logs(args.input)

    # 3️⃣ Şüpheli event'leri tespit et
    suspicious = detect_suspicious(
        logs,
        ssh_threshold=args.ssh_threshold,
        ssh_window=args.ssh_window
    )

    # 4️⃣ Risk skorlarını hesapla
    #suspicious = score_events(suspicious)

    # 5️⃣ Rapor üret
    if args.dry_run:
        print("[DRY-RUN] Rapor dosyası yazılmadı.")
    else:
        write_report(
            total=len(logs),              # ✅ total parametresi
            suspicious=suspicious,         # ✅ suspicious parametresi
            output_file=args.output,      # ✅ output_file parametresi
            output_format=args.format     # ✅ output_format parametresi (fmt değil!)
        )

    # 6️⃣ Blacklist oluştur
    if args.blacklist:
        new_ips = write_blacklist(
            suspicious,
            min_score=args.blacklist_score,
            dry_run=args.dry_run
        )

        print(f"\nBlacklist'e eklenen IP sayısı: {len(new_ips)}")

        # 7️⃣ Firewall export
        if args.export_firewall and new_ips:
            if args.dry_run:
                print("[DRY-RUN] Firewall export edilmedi.")
            else:
                if args.export_firewall == "iptables":
                    export_iptables(new_ips)
                    print("iptables script oluşturuldu")

                elif args.export_firewall == "ufw":
                    export_ufw(new_ips)
                    print("ufw rules dosyası oluşturuldu")

    print("\nAnaliz tamamlandı.")


if __name__ == "__main__":
    main()