# SMART FOX (Enhanced SNI-Spoofing)

> Bilingual README (English + فارسی)
>
> This repository is an enhanced, GUI-focused, production-oriented variant of:
> https://github.com/patterniha/SNI-Spoofing

## Thanks To The Original Creator | تشکر از سازنده اصلی

### English

Huge thanks to the original creator and maintainers of the upstream project:
https://github.com/patterniha/SNI-Spoofing

This fork builds on that work with extra hardening, tooling, UX, and packaging improvements.

### فارسی

تشکر ویژه از سازنده و نگه‌دارنده‌های پروژه اصلی:
https://github.com/patterniha/SNI-Spoofing

این نسخه با احترام به پروژه اصلی توسعه داده شده و امکانات امنیتی، پایداری، رابط کاربری و ابزارهای بیشتری به آن اضافه شده است.

---

## What Is This? | این پروژه چیست؟

### English

SMART FOX is a Windows-focused SNI spoofing toolkit for DPI bypass experiments, with:

- Core runtime (async socket relay + packet injection flow)
- Desktop GUI control panel
- Validation and scanning tools
- One-file EXE build support

### فارسی

SMART FOX یک ابزار مبتنی بر ویندوز برای تست و پیاده‌سازی سناریوهای SNI spoofing جهت عبور از DPI است که شامل موارد زیر می‌شود:

- هسته اصلی (relay غیرهمزمان + تزریق بسته)
- رابط گرافیکی دسکتاپ
- ابزارهای اعتبارسنجی و اسکن
- پشتیبانی از ساخت EXE تک‌فایل

---

## Differences From Original Upstream | تفاوت‌ها با نسخه اصلی

### English

Compared to the upstream repository, this version adds:

1. Full GUI control app (start/stop/restart core, logs, menus, shortcuts)
2. Config validation with stricter type/range checks
3. Advanced networking tunables (timeouts, retries, buffers, TCP_NODELAY)
4. Connection guardrails (global and per-client limits)
5. Built-in diagnostics:
   - simple input checker for test panel
   - Quick SNI test (single-target fast verdict)
   - Strong SNI test (multi-profile + retry verdict)
6. Live traffic monitor in GUI (upload/download speed + totals + active connections)
7. Friendlier user-facing logs for non-technical users
8. 3D-styled modern desktop UI theme
9. Admin elevation flow for Windows runtime
10. Packaging flow for onefile EXE with icon support (`build_exe.py`)
11. Better runtime stability and safer shutdown/error handling
12. Rebranded application UX as SMART FOX

### فارسی

نسبت به ریپوی اصلی، این نسخه شامل این تغییرات است:

1. رابط گرافیکی کامل (شروع/توقف/ری‌استارت هسته، لاگ زنده، منو و شورتکات)
2. اعتبارسنجی قوی‌تر برای تنظیمات با کنترل نوع داده و بازه مقادیر
3. تنظیمات پیشرفته شبکه (timeout، retry، buffer، TCP_NODELAY)
4. محدودیت‌گذاری اتصال (سراسری و به‌ازای هر IP کاربر)
5. ابزارهای عیب‌یابی داخلی:
   - بررسی ساده ورودی‌های تست
   - تست سریع SNI (نتیجه فوری)
   - تست قوی SNI (چند پروفایل TLS + چند تلاش)
6. نمایش زنده سرعت ترافیک در GUI (آپلود/دانلود + مجموع + اتصال فعال)
7. لاگ‌های ساده‌تر و قابل‌فهم‌تر برای کاربران غیرتخصصی
8. رابط گرافیکی مدرن با استایل سه‌بعدی
9. اجرای خودکار با سطح دسترسی ادمین در ویندوز
10. فرآیند ساخت EXE تک‌فایل با آیکن (`build_exe.py`)
11. پایداری بهتر در runtime و مدیریت امن‌تر خطا/خاموشی
12. بازطراحی برند و تجربه کاربری با نام SMART FOX

---

## Requirements | پیش‌نیازها

### English

- Windows
- Python 3.10+
- Administrator privileges (required by WinDivert/packet interception)

### فارسی

- ویندوز
- پایتون 3.10 یا بالاتر
- دسترسی Administrator (برای WinDivert و رهگیری بسته‌ها ضروری است)

---

## Installation | نصب

### English

```bash
pip install -r requirements.txt
```

### فارسی

```bash
pip install -r requirements.txt
```

Current dependency list includes:

- `pydivert>=3.1.0`

---

## Configuration | تنظیمات

Edit `config.json`.

### Main fields | فیلدهای اصلی

- `LISTEN_HOST`: local bind address
- `LISTEN_PORT`: local bind port
- `CONNECT_IP`: remote endpoint IP
- `CONNECT_PORT`: remote endpoint port
- `FAKE_SNI`: fake TLS SNI hostname

### Advanced fields | فیلدهای پیشرفته

- `MAX_CONNECTIONS`
- `MAX_CONNECTIONS_PER_IP`
- `HANDSHAKE_TIMEOUT_SEC`
- `RELAY_IDLE_TIMEOUT_SEC`
- `CONNECT_TIMEOUT_SEC`
- `CONNECT_RETRY_COUNT`
- `CONNECT_RETRY_DELAY_SEC`
- `RELAY_BUFFER_SIZE`
- `SOCKET_SNDBUF`
- `SOCKET_RCVBUF`
- `ENABLE_TCP_NODELAY`

### Security notes | نکات امنیتی

- Prefer `127.0.0.1` for `LISTEN_HOST` unless remote access is required.
- Keep `FAKE_SNI` as a valid DNS hostname.
- Use conservative connection limits on low-resource systems.

---

## Quick Start (CLI) | شروع سریع (خط فرمان)

### English

1. Configure `config.json`
2. Run core:

```bash
python main.py
```

### فارسی

1. فایل `config.json` را تنظیم کنید.
2. هسته را اجرا کنید:

```bash
python main.py
```

---

## Quick Start (GUI) | شروع سریع (رابط گرافیکی)

### English

Run:

```bash
python gui.py
```

Main GUI capabilities:

- Start/Stop/Restart core
- Live logs with simplified human-readable messages
- Simple Test Panel with:
  - Check Inputs
  - Quick Test
  - Strong Test
- Live traffic panel:
  - Upload speed
  - Download speed
  - Total upload/download
  - Active connection count
- 3D styled visual layout
- Advanced settings dialogs
- App window icon support (loads from `icon/*.png`)
- About dialog includes upstream credit and thanks

### فارسی

اجرا:

```bash
python gui.py
```

قابلیت‌های اصلی GUI:

- شروع/توقف/ری‌استارت هسته
- نمایش زنده لاگ با متن ساده و قابل‌فهم
- پنل ساده تست شامل:
  - Check Inputs
  - Quick Test
  - Strong Test
- پنل زنده ترافیک:
  - سرعت آپلود
  - سرعت دانلود
  - مجموع آپلود/دانلود
  - تعداد اتصال فعال
- چیدمان گرافیکی مدرن با حس سه‌بعدی
- پنجره تنظیمات پیشرفته
- پشتیبانی آیکن پنجره برنامه (از `icon/*.png`)
- بخش About همراه با ارجاع و تشکر از پروژه اصلی

---

## Test Panel (Rewritten) | پنل تست (بازنویسی‌شده)

### English

The GUI test section has been redesigned from scratch for simplicity.

Available actions:

1. `Check Inputs`
   - Verifies target IP, port, timeout, retry count, and SNI list format.
2. `Quick Test`
   - Fast check for the first SNI only.
   - Returns a simple verdict.
3. `Strong Test`
   - Tests all SNI values.
   - Uses retries + multiple TLS profiles (when available).
   - Still returns a simple verdict per SNI.

Simple output style:

- `CONNECTED`
- `NOT CONNECTED (reason: ...)`

Example:

- `SNI='example.com' on 1.2.3.4:443 -> CONNECTED (tls=TLSv1.3)`
- `SNI='example.org' on 1.2.3.4:443 -> NOT CONNECTED (reason: timeout)`

### فارسی

بخش تست در GUI از پایه بازنویسی شده تا کار با آن ساده‌تر شود.

عملیات‌های موجود:

1. `Check Inputs`
   - صحت IP، پورت، timeout، تعداد تلاش و فرمت SNI ها را بررسی می‌کند.
2. `Quick Test`
   - تست سریع روی اولین SNI.
   - خروجی فقط نتیجه ساده می‌دهد.
3. `Strong Test`
   - همه SNIها را تست می‌کند.
   - با چند تلاش و چند پروفایل TLS (در صورت پشتیبانی).
   - خروجی برای هر SNI همچنان ساده است.

نوع خروجی ساده:

- `CONNECTED`
- `NOT CONNECTED (reason: ...)`

نمونه:

- `SNI='example.com' on 1.2.3.4:443 -> CONNECTED (tls=TLSv1.3)`
- `SNI='example.org' on 1.2.3.4:443 -> NOT CONNECTED (reason: timeout)`

---

## Friendly Logs | لاگ‌های ساده

### English

Raw runtime logs are translated in GUI to friendlier messages where possible, so users can quickly understand what is happening.

### فارسی

در GUI لاگ‌های خام تا حد امکان به پیام‌های ساده‌تر تبدیل می‌شوند تا کاربر راحت‌تر متوجه وضعیت برنامه شود.

---

## About Dialog Credit | بخش About و تشکر

### English

The About dialog explicitly credits the upstream project and thanks the original creator:

- SNI-Spoofing by patterniha
- https://github.com/patterniha/SNI-Spoofing

### فارسی

در پنجره About، نام پروژه اصلی و تشکر از سازنده اصلی به صورت مستقیم نمایش داده می‌شود:

- SNI-Spoofing by patterniha
- https://github.com/patterniha/SNI-Spoofing

---

## Build Onefile EXE | ساخت EXE تک‌فایل

### English

1. Put an icon file in `icon/` (ICO preferred, PNG/JPG also supported).
2. Build:

```bash
python build_exe.py
```

Expected output:

- `dist/SMART-FOX.exe`
- `dist/config.json`

### فارسی

1. فایل آیکن را داخل پوشه `icon/` قرار دهید (ترجیحا ICO، فرمت‌های تصویری دیگر هم پشتیبانی می‌شوند).
2. بیلد بگیرید:

```bash
python build_exe.py
```

خروجی مورد انتظار:

- `dist/SMART-FOX.exe`
- `dist/config.json`

---

## Troubleshooting | رفع اشکال

### English

- Run as Administrator if packet interception fails.
- Verify `CONNECT_IP` is routable from your host.
- If scanners fail, reduce target count and increase timeout.
- If startup fails, re-check config types and ranges.

### فارسی

- اگر رهگیری بسته انجام نمی‌شود، برنامه را با دسترسی ادمین اجرا کنید.
- مطمئن شوید `CONNECT_IP` از سیستم شما route دارد.
- اگر اسکنرها خطا می‌دهند، تعداد هدف را کمتر و timeout را بیشتر کنید.
- اگر شروع سرویس شکست خورد، نوع داده و بازه مقادیر config را دوباره بررسی کنید.

---

## Project Structure | ساختار پروژه

```text
config.json
fake_tcp.py
gui.py
injecter.py
main.py
monitor_connection.py
build_exe.py
requirements.txt
utils/
  network_tools.py
  packet_templates.py
```

---
