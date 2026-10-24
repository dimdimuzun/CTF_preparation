#!/usr/bin/env bash
#
# check-ctf-tools.sh
# Перевірка наявності інструментів, згаданих у двох шпаргалках команди:
#   - ctf-cheatsheet.md (pentest-flow)
#   - ctf-crypto-forensics-pwn.md
#
# Використання:
#   chmod +x check-ctf-tools.sh
#   ./check-ctf-tools.sh
#   ./check-ctf-tools.sh | tee ctf-tools-report.txt   # щоб зберегти звіт у файл
#
set -uo pipefail

# ==== Шляхи до ручних установок — підправте під свою структуру ====
ROCKYOU_PATH="${ROCKYOU_PATH:-/usr/share/wordlists/rockyou.txt}"
GTFOBINS_DIR="${GTFOBINS_DIR:-$HOME/tools/gtfobins}"
RSACTFTOOL_DIR="${RSACTFTOOL_DIR:-$HOME/tools/RsaCtfTool}"
LINPEAS_PATH="${LINPEAS_PATH:-$HOME/tools/linpeas.sh}"
CYBERCHEF_DIR="${CYBERCHEF_DIR:-$HOME/tools/CyberChef}"
PHP_SHELL_PATH="${PHP_SHELL_PATH:-$HOME/tools/php-reverse-shell.php}"
PWNDBG_DIR="${PWNDBG_DIR:-$HOME/pwndbg}"

PASS=0
FAIL=0
declare -a MISSING   # "назва|інструкція встановлення"

# ---- Перевірка одного пункту ----
# check "назва для таблиці" <cmd|file|dir|py> "аргумент" "інструкція встановлення"
check() {
    local display="$1" type="$2" arg="$3" hint="$4"
    local ok=1

    case "$type" in
        cmd) command -v "$arg" >/dev/null 2>&1 && ok=0 ;;
        file) [ -f "$arg" ] && ok=0 ;;
        dir) [ -d "$arg" ] && [ -n "$(ls -A "$arg" 2>/dev/null)" ] && ok=0 ;;
        py) python3 -c "import $arg" >/dev/null 2>&1 && ok=0 ;;
    esac

    if [ "$ok" -eq 0 ]; then
        printf "  %-30s [x]\n" "$display"
        PASS=$((PASS + 1))
    else
        printf "  %-30s [ ]\n" "$display"
        FAIL=$((FAIL + 1))
        MISSING+=("$display|$hint")
    fi
}

section() {
    echo ""
    echo "== $1 =="
}

echo "Перевірка CTF-інструментів — $(date '+%Y-%m-%d %H:%M') на $(hostname)"
echo "============================================================"

# ---------------------------------------------------------------
# ЧАСТИНА 1: ctf-cheatsheet.md (pentest-flow)
# ---------------------------------------------------------------

section "1-2. Розвідка та веброзвідка"
check "netdiscover"      cmd  netdiscover   "sudo apt install netdiscover -y"
check "nmap"              cmd  nmap          "sudo apt install nmap -y"
check "gobuster"          cmd  gobuster      "sudo apt install gobuster -y"
check "dirb"               cmd  dirb          "sudo apt install dirb -y"
check "dirsearch"         cmd  dirsearch     "sudo apt install dirsearch -y  (або: git clone https://github.com/maurosoria/dirsearch)"
check "wpscan"             cmd  wpscan        "sudo apt install wpscan -y  (або: sudo gem install wpscan)"
check "searchsploit"      cmd  searchsploit  "sudo apt install exploitdb -y"

section "2b. SMB-розвідка"
check "enum4linux"        cmd  enum4linux   "sudo apt install enum4linux -y"
check "smbclient"          cmd  smbclient    "sudo apt install smbclient -y"

section "3. Паролі та брутфорс"
check "fcrackzip"          cmd  fcrackzip    "sudo apt install fcrackzip -y"
check "john"                cmd  john         "sudo apt install john -y"
check "zip2john"           cmd  zip2john     "входить у пакет john: sudo apt install john -y"
check "hashid"              cmd  hashid       "sudo apt install hashid -y  (або: pip install hashid --break-system-packages)"
check "hashcat"             cmd  hashcat      "sudo apt install hashcat -y"
check "hydra"                cmd  hydra        "sudo apt install hydra -y"
check "medusa"               cmd  medusa       "sudo apt install medusa -y"

section "4. Знайдені файли й креди"
check "gpg"                  cmd  gpg          "sudo apt install gnupg -y"
check "mysql-client"      cmd  mysql        "sudo apt install mariadb-client -y  (або: default-mysql-client)"
check "mysqldump"           cmd  mysqldump    "входить у mariadb-client / default-mysql-client"

section "5. RCE / SQLi"
check "sqlmap"               cmd  sqlmap       "sudo apt install sqlmap -y"
check "msfvenom"            cmd  msfvenom     "sudo apt install metasploit-framework -y"

section "6. Reverse shell та перенесення файлів"
check "nc / netcat"         cmd  nc           "sudo apt install netcat-traditional -y  (або: ncat через nmap)"
check "curl"                  cmd  curl         "sudo apt install curl -y"
check "wget"                  cmd  wget         "sudo apt install wget -y"
check "ssh / scp"            cmd  ssh          "sudo apt install openssh-client -y"
check "python3"              cmd  python3     "sudo apt install python3 -y"

section "8. Підвищення привілеїв"
check "getcap"               cmd  getcap      "sudo apt install libcap2-bin -y"
check "strings"               cmd  strings      "sudo apt install binutils -y"
check "gcc"                    cmd  gcc           "sudo apt install gcc -y"
check "perl"                   cmd  perl          "sudo apt install perl -y"
check "vim"                     cmd  vim           "sudo apt install vim -y"
check "ftp-client"         cmd  ftp           "sudo apt install ftp -y"
check "locate"                 cmd  locate       "sudo apt install mlocate -y  (далі: sudo updatedb)"

section "9. Кодування та стеганографія"
check "stegcracker"          cmd  stegcracker "pip install stegcracker --break-system-packages"
check "steghide"              cmd  steghide     "sudo apt install steghide -y"
check "binwalk"                cmd  binwalk      "sudo apt install binwalk -y"
check "zsteg"                   cmd  zsteg         "sudo gem install zsteg"
check "xxd"                      cmd  xxd           "sudo apt install vim-common -y  (зазвичай вже є)"

section "10. Офлайн-ресурси для флешки/команди"
check "git"                      cmd  git           "sudo apt install git -y"
check "GTFOBins (local copy)"  dir  "$GTFOBINS_DIR"   "git clone https://github.com/GTFOBins/GTFOBins.github.io.git $GTFOBINS_DIR"
check "rockyou.txt (unzipped)" file "$ROCKYOU_PATH"   "sudo gzip -d /usr/share/wordlists/rockyou.txt.gz"
check "linpeas.sh"               file "$LINPEAS_PATH"    "wget -O $LINPEAS_PATH https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
check "php-reverse-shell.php"   file "$PHP_SHELL_PATH"  "wget -O $PHP_SHELL_PATH https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php"
check "CyberChef (offline build)" dir  "$CYBERCHEF_DIR"   "Завантажити CyberChef_vX.X.X.zip з https://github.com/gchq/CyberChef/releases і розпакувати в $CYBERCHEF_DIR"

# ---------------------------------------------------------------
# ЧАСТИНА 2: ctf-crypto-forensics-pwn.md
# ---------------------------------------------------------------

section "Crypto"
check "openssl"                  cmd  openssl      "sudo apt install openssl -y"
check "RsaCtfTool (local copy)" dir "$RSACTFTOOL_DIR" "git clone https://github.com/RsaCtfTool/RsaCtfTool.git $RSACTFTOOL_DIR"
check "python: pycryptodome"    py   Crypto        "pip install pycryptodome --break-system-packages"
check "python: base58"           py   base58        "pip install base58 --break-system-packages"

section "Forensics"
check "exiftool"                  cmd  exiftool     "sudo apt install libimage-exiftool-perl -y"
check "foremost"                   cmd  foremost      "sudo apt install foremost -y"
check "scalpel"                     cmd  scalpel        "sudo apt install scalpel -y"
check "mmls (sleuthkit)"          cmd  mmls           "sudo apt install sleuthkit -y"
check "volatility / volatility3"  cmd  vol.py        "pip install volatility3 --break-system-packages  (або: sudo apt install volatility3 -y)"
check "wireshark"                  cmd  wireshark      "sudo apt install wireshark -y"
check "tshark"                      cmd  tshark         "sudo apt install tshark -y"
check "pdf-parser"                 cmd  pdf-parser.py "sudo apt install pdf-parser -y  (або: pip install pdfid --break-system-packages)"
check "oletools (olevba)"         cmd  olevba         "pip install oletools --break-system-packages"

section "Pwn"
check "checksec"                   cmd  checksec      "sudo apt install checksec -y"
check "gdb"                          cmd  gdb            "sudo apt install gdb -y"
check "objdump"                     cmd  objdump        "sudo apt install binutils -y"
check "ltrace"                       cmd  ltrace          "sudo apt install ltrace -y"
check "strace"                       cmd  strace          "sudo apt install strace -y"
check "file"                          cmd  file            "sudo apt install file -y"
check "python: pwntools"           py   pwn             "pip install pwntools --break-system-packages"
check "pwndbg/GEF (gdb plugin)"    dir  "$PWNDBG_DIR"   "git clone https://github.com/pwndbg/pwndbg $PWNDBG_DIR && cd $PWNDBG_DIR && ./setup.sh"

# ---------------------------------------------------------------
# ПІДСУМОК
# ---------------------------------------------------------------

echo ""
echo "============================================================"
printf "Разом: %d присутньо, %d відсутньо (з %d)\n" "$PASS" "$FAIL" "$((PASS + FAIL))"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "============================================================"
    echo "ДОДАТОК: інструкції встановлення для відсутніх інструментів"
    echo "============================================================"
    for entry in "${MISSING[@]}"; do
        name="${entry%%|*}"
        hint="${entry#*|}"
        echo ""
        echo "• $name"
        echo "  $hint"
    done
else
    echo ""
    echo "Усе на місці — нічого встановлювати не треба."
fi
