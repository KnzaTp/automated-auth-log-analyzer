import re
import csv
import json
from collections import defaultdict
from datetime import datetime, timezone

# إعدادات التحليل
LOG_FILE = "sample_auth.log"
CSV_REPORT_FILE = "security_report.csv"
JSON_REPORT_FILE = "flagged_ips.json"
BRUTE_FORCE_THRESHOLD = 5  # عدد المحاولات الفاشلة التي تُعتبر هجوماً

# تعابير نمطية (Regex) لاستخراج الوقت واسم المستخدم وعنوان IP من سطور السجل
FAILED_PATTERN = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
ACCEPTED_PATTERN = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


def parse_auth_log(file_path):
    """قراءة ملف السجلات وتجميع المحاولات الفاشلة والناجحة لكل عنوان IP."""
    ip_activity = defaultdict(lambda: {
        "failed_attempts": 0,
        "successful_logins": 0,
        "targeted_users": set(),
        "compromised_users": set(),
        "first_seen": None,
        "last_seen": None,
    })

    total_lines = 0

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            total_lines += 1

            failed_match = FAILED_PATTERN.search(line)
            if failed_match:
                ts = failed_match.group("timestamp")
                user = failed_match.group("user")
                ip = failed_match.group("ip")

                record = ip_activity[ip]
                record["failed_attempts"] += 1
                record["targeted_users"].add(user)
                record["first_seen"] = record["first_seen"] or ts
                record["last_seen"] = ts
                continue

            accepted_match = ACCEPTED_PATTERN.search(line)
            if accepted_match:
                ts = accepted_match.group("timestamp")
                user = accepted_match.group("user")
                ip = accepted_match.group("ip")

                record = ip_activity[ip]
                record["successful_logins"] += 1
                record["compromised_users"].add(user)
                record["first_seen"] = record["first_seen"] or ts
                record["last_seen"] = ts

    return total_lines, ip_activity


def detect_threats(ip_activity, threshold):
    """تصنيف عناوين الـ IP المشبوهة وتحديد مستوى الخطورة لكل منها."""
    flagged = []

    for ip, stats in ip_activity.items():
        if stats["failed_attempts"] >= threshold:
            # إذا نجح المهاجم في الدخول بعد عدة محاولات فاشلة فهذه حالة اختراق حرج
            if stats["successful_logins"] > 0:
                severity = "CRITICAL"
                alert_type = "Brute-Force Followed by Successful Login"
                recommended_action = "Block IP immediately and reset compromised account password"
            else:
                severity = "HIGH"
                alert_type = "Potential Brute-Force Attack"
                recommended_action = "Block IP at firewall and monitor targeted accounts"

            flagged.append({
                "ip_address": ip,
                "severity": severity,
                "alert_type": alert_type,
                "failed_attempts": stats["failed_attempts"],
                "successful_logins": stats["successful_logins"],
                "targeted_users": sorted(stats["targeted_users"]),
                "compromised_users": sorted(stats["compromised_users"]),
                "first_seen": stats["first_seen"],
                "last_seen": stats["last_seen"],
                "recommended_action": recommended_action,
            })

    # ترتيب التنبيهات من الأخطر (CRITICAL) إلى الأقل
    severity_rank = {"CRITICAL": 1, "HIGH": 2}
    flagged.sort(key=lambda item: (severity_rank[item["severity"]], -item["failed_attempts"]))
    return flagged


def export_reports(flagged_ips, total_lines):
    """تصدير نتائج التحليل إلى ملفي CSV و JSON."""
    # 1) حفظ تقرير CSV
    fieldnames = [
        "ip_address",
        "severity",
        "alert_type",
        "failed_attempts",
        "successful_logins",
        "targeted_users",
        "compromised_users",
        "first_seen",
        "last_seen",
        "recommended_action",
    ]
    with open(CSV_REPORT_FILE, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for entry in flagged_ips:
            row = entry.copy()
            row["targeted_users"] = ", ".join(entry["targeted_users"])
            row["compromised_users"] = ", ".join(entry["compromised_users"]) or "None"
            writer.writerow(row)

    # 2) حفظ تقرير JSON
    json_payload = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_log": LOG_FILE,
        "total_log_lines_parsed": total_lines,
        "brute_force_threshold": BRUTE_FORCE_THRESHOLD,
        "total_flagged_ips": len(flagged_ips),
        "alerts": flagged_ips,
    }
    with open(JSON_REPORT_FILE, "w", encoding="utf-8") as json_file:
        json.dump(json_payload, json_file, indent=4)


def main():
    total_lines, ip_activity = parse_auth_log(LOG_FILE)
    flagged_ips = detect_threats(ip_activity, BRUTE_FORCE_THRESHOLD)
    export_reports(flagged_ips, total_lines)

    print("=" * 65)
    print("AUTOMATED AUTHENTICATION LOG ANALYSIS SUMMARY")
    print("=" * 65)
    print(f"Total log entries parsed : {total_lines}")
    print(f"Unique IPs observed      : {len(ip_activity)}")
    print(f"Malicious IPs flagged    : {len(flagged_ips)}")
    print("-" * 65)

    for alert in flagged_ips:
        print(f"[{alert['severity']}] IP: {alert['ip_address']} | {alert['alert_type']}")
        print(f"   Failed: {alert['failed_attempts']} | Successful: {alert['successful_logins']}")
        print(f"   Targeted Users: {', '.join(alert['targeted_users'])}")
        print(f"   Action: {alert['recommended_action']}\n")

    print(f"Reports exported successfully: {CSV_REPORT_FILE}, {JSON_REPORT_FILE}")


if __name__ == "__main__":
    main()
