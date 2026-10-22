# CyberOpsSuite

**یه جعبه‌ابزار امنیتی ماژولار و چندسکویی برای مدیران ویندوز و لینوکس.**

CyberOpsSuite هفت ابزار امنیتی مستقل رو زیر یه داشبورد یکپارچه جمع می‌کنه.
هر ماژول توی پروسه‌ی خودش اجرا می‌شه، از یه تم تیره‌ی مشترک استفاده می‌کنه،
و می‌تونه به‌صورت مستقل هم اجرا بشه. هر ماژول یه راهنمای **How to Use**
داخلی داره (در ماژول‌های چندصفحه‌ای، راهنما مخصوص هر صفحه‌ست).

> **📌 یه نکته درباره‌ی نحوه‌ی ساخت این پروژه**
>
> CyberOpsSuite با **وایب کدینگ** ساخته شده — یه فرآیند همکاری
> تکراری بین یه انسان و یه دستیار هوش مصنوعی. کد از طریق گفتگوی
> طبیعی نوشته، بازبینی و اصلاح شده، نه با برنامه‌ریزی قدم‌به‌قدم
> سنتی.
>
> ما به شفافیت اعتقاد داریم. پروژه کار می‌کنه، ولی محصول همکاری
> انسان-هوش مصنوعیه، نه تلاش یه انسان تنها. مشارکت، گزارش باگ، و
> بازخورد سازنده خوش‌آمده.

---

## ماژول‌ها

| ماژول | کاربرد | سیستم‌عامل |
|-------|--------|------------|
| Firewall Manager | مدیریت قوانین فایروال (netsh / ufw / nft / iptables) | ویندوز + لینوکس |
| Event Log Analyzer | خواندن لاگ‌های رویداد ویندوز، ژورنال لینوکس، یا JSON Lines | ویندوز + لینوکس |
| Network Mapper | اسکن هم‌زمان ICMP + TCP برای کشف هاست و پورت | ویندوز + لینوکس |
| DHCP Lease Viewer | مشاهده لیزهای DHCP محلی و کوئری سرورهای راه دور | ویندوز + لینوکس |
| Server Monitor | مانیتور و کنترل سرویس‌های محلی با Health Score و نمودار | ویندوز + لینوکس |
| VPN Manager | مدیریت پروفایل‌های VLESS/VMess با Xray-core و Smart Auto-Switch | ویندوز + لینوکس |
| IP Rotator | تغییر IP عمومی با شبکه Tor | ویندوز + لینوکس |

---

## ویژگی‌های کلیدی

- **داشبورد یکپارچه تیره** با وضعیت زنده سیستم، آمار سراسری و آخرین فعالیت‌ها
- **راهنمای How to Use داخلی** در تمام ماژول‌ها (در ماژول‌های چندصفحه‌ای، مخصوص هر صفحه)
- **عملیات Thread-based** — رابط کاربری هرگز هنگ نمی‌کنه
- **پیش‌فرض Read-only** — هیچ ماژولی بدون اقدام صریح، سیستم راه دور رو تغییر نمی‌ده
- **چندسکویی** — ویندوز ۱۰/۱۱/Server 2019+ و لینوکس (مبتنی بر systemd)
- **لاگ‌گیری در AppData** — هر ماژول یه فایل لاگ برای عیب‌یابی می‌نویسه
- **نوتیفیکیشن دسکتاپ** برای رویدادهای حیاتی (Server Monitor)
- **Smart Auto-Switch** برای VPN Manager — تأخیر رو تست می‌کنه و به سریع‌ترین سرور سوییچ می‌کنه
- **سنجش سرعت زنده** برای VPN Manager (Down/Up به Mbps)
- **Health Score و نمودار دایره‌ای** برای Server Monitor
- **تاریخچه اسکن با مقایسه** برای Network Mapper
- **کوئری DHCP راه دور** با WinRM (ویندوز) یا SSH (لینوکس)
- **فرمت‌های خروجی متعدد** — JSON، CSV، HTML

---

## شروع سریع

### روش ۱ — اجرای داشبورد (توصیه می‌شه)

    python -m dashboard.main

بعد روی دکمه **Open module** هر کارت کلیک کن.

### روش ۲ — اجرای یه ماژول مستقل

    python -m firewall_manager.gui.main
    python -m event_log_analyzer.gui.main
    python -m network_mapper.gui.main
    python -m dhcp_lease_viewer.gui.main
    python -m server_monitor.gui.main
    python -m vpn_manager.gui.main
    python -m ip_rotator.gui.main

---

## پیش‌نیازها

* **Python 3.10+** (تست‌شده روی 3.14)
* **pip**

### نصب وابستگی‌ها

    pip install -r requirements.txt

### پکیج‌های اختیاری

| پکیج | استفاده در | کاربرد |
|------|------------|--------|
| `plyer` | Server Monitor | نوتیفیکیشن دسکتاپ برای توقف سرویس‌های حیاتی |
| `paramiko` | DHCP Lease Viewer | SSH با پسورد (بک‌اند لینوکس راه دور) |
| `stem` | IP Rotator | اتصال به کنترلر Tor |

### پیش‌نیازهای هر ماژول

| ماژول | ویندوز | لینوکس |
|-------|--------|--------|
| Firewall Manager | Administrator | sudo + ufw/nft/iptables |
| Event Log Analyzer | PowerShell | journalctl + systemd-journal |
| Network Mapper | — | — |
| DHCP Lease Viewer | PowerShell + WinRM (RSAT-DHCP برای ریموت) | systemd-networkd + SSH |
| Server Monitor | Administrator | sudo |
| VPN Manager | xray.exe توی bin/ | xray توی bin/ |
| IP Rotator | Tor + ControlPort | Tor + ControlPort |

---

## ساختار پروژه

    CyberOpsSuite/
    |-- dashboard/              لانچر همه ماژول‌ها
    |-- core/                   کد مشترک
    |   |-- theme.py
    |   |-- gui/treeview_style.py
    |   |-- utils/
    |       |-- icons.py
    |       |-- paths.py
    |       |-- subprocess_utils.py
    |-- firewall_manager/
    |-- event_log_analyzer/
    |-- network_mapper/
    |-- dhcp_lease_viewer/
    |-- server_monitor/
    |-- vpn_manager/
    |-- ip_rotator/
    |-- assets/icons/
    |-- bin/                    Xray-core + wintun + geoip/geosite
    |-- data/                   داده‌های نمونه
    |-- exports/                خروجی‌های زمان اجرا
    |-- requirements.txt
    |-- README.md
    |-- README.FA.md

---

## تنظیمات

تنظیمات هر کاربر:

| سیستم‌عامل | مسیر |
|------------|------|
| **ویندوز** | `%APPDATA%\CyberOpsSuite\<Module>\` |
| **لینوکس** | `~/.config/CyberOpsSuite/<Module>/` |

پوشه `data/` فقط شامل فایل‌های **نمونه** برای مرجع هست.

---

## ساخت فایل اجرایی (EXE)

    pip install pyinstaller
    python build.py

خروجی توی پوشه `dist/` قرار می‌گیره.

---

## پشتیبانی سیستم‌عامل

* ✅ ویندوز ۱۰ / ۱۱ / Server 2019+
* ✅ لینوکس (توزیع‌های مبتنی بر systemd)
* ❌ macOS — پشتیبانی نمی‌شه

---

## استفاده مسئولانه

از CyberOpsSuite فقط روی سیستم‌هایی استفاده کن که **مالکش هستی**
یا **اجازه صریح** برای ارزیابی داری. اسکن شبکه، تغییر فایروال، و
تحلیل لاگ می‌تونه پیامدهای قانونی و عملیاتی روی شبکه‌هایی داشته باشه
که مدیریتشون نمی‌کنی.

---

## توسعه‌ی Suite

برای اضافه کردن یه ماژول جدید:

1. یه پکیج با همین ساختار بساز:

       my_module/
       |-- core/         منطق
       |-- gui/main.py   رابط CustomTkinter
       |-- api/main.py   FastAPI اختیاری
       |-- cli/main.py   CLI اختیاری

2. از `core.theme`، `core.utils.icons`، `core.utils.paths` استفاده کن
3. یه entry به لیست `TOOLS` توی `dashboard/main.py` اضافه کن
4. نام EXE ماژول رو به `MODULE_TO_EXE` توی `dashboard/main.py` اضافه کن
5. یه راهنمای How to Use مشابه بقیه ماژول‌ها اضافه کن

---

## کلیدهای میانبر

| میانبر | عملکرد |
|--------|--------|
| F5 / Ctrl+R | رفرش صفحه فعلی |
| F1 | باز کردن About |
| Enter | اتصال / نمایش جزئیات |
| Delete | حذف آیتم انتخابی |
| Escape | بستن دیالوگ / پاک کردن فیلترها |
| Ctrl+O | باز کردن فایل (Event Log Analyzer) |
| Ctrl+F | فوکوس روی جستجو |
| Ctrl+L | پاک کردن فیلترها |
| Ctrl+E | خروجی CSV |

---

## مجوز

این پروژه به‌صورت as-is برای استفاده آموزشی و مدیریتی مجاز ارائه میشه.
باینری‌های سوم‌شخص (`xray`، `wintun`) تحت مجوز خودشون هستن —
به `bin/LICENSE` و `bin/LICENSE-wintun.txt` مراجعه کن.

---

## تشکر

* [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) — UI مدرن تیره
* [Xray-core](https://github.com/XTLS/Xray-core) — موتور VPN
* [Wintun](https://www.wintun.net/) — درایور TUN ویندوز
* [FastAPI](https://fastapi.tiangolo.com/) — APIهای HTTP اختیاری
* [Plyer](https://github.com/kivy/plyer) — نوتیفیکیشن‌های دسکتاپ
* [Paramiko](https://www.paramiko.org/) — SSH با پسورد
* [Stem](https://stem.torproject.org/) — کنترل Tor