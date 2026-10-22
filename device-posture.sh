#!/bin/zsh
# device-posture.sh: one-screen macOS security check for ISO 27001 device evidence (Macs without MDM).
# All green → an evidence table (built-in macOS command + its output) to screenshot.
# Anything failing → a plain-English checklist with fix steps instead.
#
# Usage: zsh device-posture.sh              contractor / personal Mac (default; collects the least)
#        zsh device-posture.sh --company    company-owned Mac (adds Bitdefender, config, apps list)
#        curl -fsSL <url> | zsh -s -- --company
# No sudo required. Changes nothing, except writing the apps list to the Desktop in --company mode.

emulate -L zsh
VERSION=2026.10.22

# ── Policy ───────────────────────────────────────────────────────────────
MIN_MACOS_MAJOR=15          # oldest macOS still receiving security fixes
MAX_DISPLAY_SLEEP_MIN=5     # display turns off within this many minutes (every power source)
MAX_LOCK_DELAY_SEC=5        # password required within this many seconds of display off
MAX_DEFS_AGE_DAYS=3         # Bitdefender definitions no older than this
MAX_CLOCK_DRIFT_SEC=2       # clock within this many seconds of Apple's time server
COMPANY_AV="Bitdefender"
COMPANY_AV_PROCESS="BDLDaemon"
BD_SIGNATURES=/Library/Bitdefender/AVP/signatures
BD_APP="/Applications/Endpoint Security for Mac.app"

# Anti-virus accepted on contractor Macs: process name → product
typeset -A CONTRACTOR_AV=(
  BDLDaemon                     Bitdefender
  wdavdaemon                    "Microsoft Defender"
  sentineld                     SentinelOne
  com.crowdstrike.falcon.Agent  "CrowdStrike Falcon"
  SophosScanD                   Sophos
  RTProtectionDaemon            Malwarebytes
)

company=0
[[ " $* " == *" --company "* ]] && company=1

G=$'\e[32m' R=$'\e[31m' B=$'\e[1m' D=$'\e[2m' X=$'\e[0m'
typeset -a ids
typeset -A ok label plain evcmd evout

record() {  # record <id> <ok:1|0> <label> <plain-English result> <evidence command> <evidence output>
  ids+=$1; ok[$1]=$2; label[$1]=$3; plain[$1]=$4; evcmd[$1]=$5; evout[$1]=$6
}

minutes() {  # minutes <seconds> → "immediately" / "after 30 seconds" / "after 5 minutes"
  (( $1 == 0 )) && { print immediately; return }
  (( $1 < 60 )) && { print "after $1 seconds"; return }
  print "after $(( $1 / 60 )) minutes"
}

print "Checking this Mac (takes about 10 seconds)…"

# ── Identity ─────────────────────────────────────────────────────────────
hw=$(system_profiler SPHardwareDataType 2>/dev/null)
model=$(awk -F': ' '/Model Name/{print $2}' <<< $hw)
serial=$(awk -F': ' '/Serial Number/{print $2}' <<< $hw)
host=$(scutil --get ComputerName)
os_ver=$(sw_vers -productVersion); os_build=$(sw_vers -buildVersion); os_major=${os_ver%%.*}

# ── Checks for every Mac ─────────────────────────────────────────────────
if (( os_major >= MIN_MACOS_MAJOR )); then
  record macos 1 "macOS version" "macOS $os_ver" "sw_vers -productVersion" "$os_ver"
else
  record macos 0 "macOS version" "macOS $os_ver no longer gets security fixes" "sw_vers -productVersion" "$os_ver"
fi

# Only same-major updates count; optional major upgrades are ignored
su=$(softwareupdate --list 2>&1)
pending=(${(f)"$(awk -v maj=$os_major -F'Title: |, Version: |, Size' '
  /Title:/ { split($3, v, "."); if ($2 ~ /^macOS/ && v[1] != maj) next; print $2 " " $3 }' <<< $su)"})
if [[ $su == *"No new software available"* ]]; then
  record updates 1 "Software updates" "Up to date" "softwareupdate --list" "No new software available."
elif (( ${#pending} )); then
  record updates 0 "Software updates" "${#pending} waiting to install: ${(j:, :)pending}" \
    "softwareupdate --list" "${#pending} pending: ${(j:, :)pending}"
elif [[ $su == *"Title:"* ]]; then
  record updates 1 "Software updates" "Up to date" "softwareupdate --list" "only optional macOS upgrades available"
else
  record updates 0 "Software updates" "Couldn't check. Are you connected to the internet?" \
    "softwareupdate --list" "could not reach Apple"
fi

# Unset keys mean macOS's default, which is on
su_pref() { defaults read /Library/Preferences/com.apple.SoftwareUpdate $1 2>/dev/null || print 1 }
au_check=$(su_pref AutomaticCheckEnabled) au_crit=$(su_pref CriticalUpdateInstall) au_data=$(su_pref ConfigDataInstall)
au_ok=$(( au_check == 1 && au_crit == 1 && au_data == 1 ))
record autoupdate $au_ok "Auto security updates" "$( (( au_ok )) && print On || print Off)" \
  "defaults read com.apple.SoftwareUpdate" "AutomaticCheck=$au_check CriticalUpdate=$au_crit ConfigData=$au_data"

fv=$(fdesetup status 2>&1 | head -1)
case $fv in
  *"is On."*) record filevault 1 "Disk encryption" "On" "fdesetup status" "$fv" ;;
  *progress*) record filevault 0 "Disk encryption" "Still encrypting. Keep the Mac plugged in" "fdesetup status" "$fv" ;;
  *)          record filevault 0 "Disk encryption" "Off" "fdesetup status" "$fv" ;;
esac

auth=$(dscl . -authonly "$USER" "" 2>&1); auth_rc=$?
if (( auth_rc != 0 )) && [[ $auth == *eDSAuthFailed* ]]; then
  record password 1 "Login password" "Set" "dscl . -authonly \$USER \"\"" "blank password rejected (eDSAuthFailed)"
else
  record password 0 "Login password" "No password set" "dscl . -authonly \$USER \"\"" "blank password accepted"
fi

autologin=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)
if [[ -z $autologin ]]; then
  record autologin 1 "Automatic login" "Off" "defaults read …loginwindow autoLoginUser" "not set"
else
  record autologin 0 "Automatic login" "On (logs straight in as $autologin)" "defaults read …loginwindow autoLoginUser" "$autologin"
fi

# Every power source must turn the display off in time; 0 means never
sleep_ok=1; sleep_plain=() sleep_ev=()
for src mins in $(pmset -g custom | awk '/Power:/{src=$1} /displaysleep/{print src, $2}'); do
  (( mins == 0 || mins > MAX_DISPLAY_SLEEP_MIN )) && sleep_ok=0
  sleep_ev+="$src $mins"
  case $src in Battery) where="on battery" ;; AC) where="when plugged in" ;; *) where="on $src" ;; esac
  (( mins == 0 )) && sleep_plain+="never $where" || sleep_plain+="after $mins min $where"
done
record displaysleep $sleep_ok "Screen turns off" "${(j:, :)sleep_plain}" "pmset -g custom" "displaysleep ${(j:, :)sleep_ev}"

lock=$(sysadminctl -screenLock status 2>&1 | tail -1 | sed 's/.*\] //')
case $lock in
  *immediate*) delay=0 ;;
  *seconds*)   delay=${${lock##*is }%% seconds*} ;;
  *)           delay=-1 ;;
esac
if (( delay < 0 )); then
  record lockdelay 0 "Password on wake" "Not required" "sysadminctl -screenLock status" "$lock"
else
  record lockdelay $(( delay <= MAX_LOCK_DELAY_SEC )) "Password on wake" "Required $(minutes $delay)" \
    "sysadminctl -screenLock status" "$lock"
fi

fw=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1)
fw_ok=$([[ $fw == *"is enabled"* ]] && print 1 || print 0)
record firewall $fw_ok "Firewall" "$( (( fw_ok )) && print On || print Off)" "socketfilterfw --getglobalstate" "$fw"

# Bitdefender definitions: newest file under its signatures folder
defs_age=-1 defs_date=""
if [[ -d $BD_SIGNATURES ]]; then
  newest=$(find $BD_SIGNATURES -type f -exec stat -f %m {} + 2>/dev/null | sort -n | tail -1)
  [[ -n $newest ]] && { defs_age=$(( ($(date +%s) - newest) / 86400 )); defs_date=$(date -r $newest '+%d %b %H:%M') }
fi

if (( company )); then av_procs=($COMPANY_AV_PROCESS); else av_procs=(${(k)CONTRACTOR_AV}); fi
av_name="" av_pid=""
for proc in $av_procs; do
  av_pid=$(pgrep -f $proc | head -1)
  [[ -n $av_pid ]] && { av_name=${CONTRACTOR_AV[$proc]:-$COMPANY_AV}; av_proc=$proc; break }
done
av_label=$( (( company )) && print "Anti-virus ($COMPANY_AV)" || print "Anti-virus")
if [[ -z $av_pid ]]; then
  missing=$( (( company )) && print "$COMPANY_AV is not running" || print "No anti-virus found")
  record antivirus 0 $av_label $missing "pgrep -f ${av_procs[1]}" "no process"
elif [[ $av_name == Bitdefender ]] && (( defs_age < 0 || defs_age > MAX_DEFS_AGE_DAYS )); then
  record antivirus 0 $av_label "Running, but virus definitions are out of date (${defs_date:-unknown})" \
    "pgrep -f $av_proc; stat signatures" "pid $av_pid · definitions ${defs_date:-unknown}"
elif [[ $av_name == Bitdefender ]]; then
  record antivirus 1 $av_label "$av_name running, definitions updated $defs_date" \
    "pgrep -f $av_proc; stat signatures" "pid $av_pid · definitions $defs_date"
else
  record antivirus 1 $av_label "$av_name running" "pgrep -f $av_proc" "pid $av_pid ($av_name)"
fi

# ── Company-owned Macs only ──────────────────────────────────────────────
if (( company )); then
  gk=$(spctl --status 2>&1)
  gk_ok=$([[ $gk == "assessments enabled" ]] && print 1 || print 0)
  record gatekeeper $gk_ok "App safety (Gatekeeper)" "$( (( gk_ok )) && print On || print Off)" "spctl --status" "$gk"

  sip=$(csrutil status 2>&1)
  sip_ok=$([[ $sip == *"enabled."* ]] && print 1 || print 0)
  record sip $sip_ok "System protection (SIP)" "$( (( sip_ok )) && print On || print Off)" "csrutil status" "$sip"

  ntp=$(sntp -t 2 time.apple.com 2>&1 | tail -1)
  drift=${ntp%% *}
  if [[ $drift == [+-][0-9]* ]]; then
    drift_ok=$(awk -v d=$drift -v m=$MAX_CLOCK_DRIFT_SEC 'BEGIN{a = d < 0 ? -d : d; print (a <= m ? 1 : 0)}')
    record clock $drift_ok "Clock in sync" "$( (( drift_ok )) && print "Yes" || print "No, it's ${drift#+} seconds out")" \
      "sntp time.apple.com" "${ntp% *}"
  else
    record clock 0 "Clock in sync" "Couldn't check. Are you connected to the internet?" "sntp time.apple.com" "$ntp"
  fi

  listening=$(netstat -anp tcp 2>/dev/null | awk '$NF=="LISTEN"{print $4}')
  typeset -A services=(22 "Remote Login" 445 "File Sharing" 5900 "Screen Sharing")
  on=() on_ports=()
  for port in 22 445 5900; do
    print -r -- $listening | grep -qE "[.:]$port\$" && { on+=${services[$port]}; on_ports+=":$port" }
  done
  if (( ${#on} )); then
    record sharing 0 "Remote access & sharing" "${(j:, :)on} turned on" "netstat -an | grep LISTEN" "listening on ${(j: :)on_ports}"
  else
    record sharing 1 "Remote access & sharing" "Off" "netstat -an | grep LISTEN" "nothing on :22 :445 :5900"
  fi

  apps_file=~/Desktop/apps-$serial-$(date +%F).txt
  {
    print "Installed applications · $model · serial $serial · $host · $USER · $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    for app in ${(f)"$(find /Applications ~/Applications -maxdepth 3 -name '*.app' -prune 2>/dev/null | sort -f)"}; do
      printf "%s\t%s\n" "${${app:t}%.app}" "$(defaults read "$app/Contents/Info" CFBundleShortVersionString 2>/dev/null)"
    done
  } > $apps_file 2>/dev/null
  if [[ -s $apps_file ]]; then
    n_apps=$(( $(wc -l < $apps_file) - 1 ))
    apps_sha=$(shasum -a 256 $apps_file | cut -c1-16)
    record apps 1 "Installed apps list" "$n_apps apps saved to Desktop/${apps_file:t}" \
      "find /Applications -name '*.app'" "$n_apps apps → Desktop/${apps_file:t}"
  else
    record apps 0 "Installed apps list" "Couldn't save the list to your Desktop" "find /Applications -name '*.app'" "write failed"
  fi
fi

# ── Fix cards: what to do, and why it matters ────────────────────────────
SETTINGS="Open System Settings (click the Apple menu at the top-left of the screen, then System Settings)"
typeset -A PANE=(
  macos        com.apple.Software-Update-Settings.extension
  updates      com.apple.Software-Update-Settings.extension
  autoupdate   com.apple.Software-Update-Settings.extension
  filevault    com.apple.settings.PrivacySecurity.extension
  gatekeeper   com.apple.settings.PrivacySecurity.extension
  password     com.apple.Users-Groups-Settings.extension
  autologin    com.apple.Users-Groups-Settings.extension
  displaysleep com.apple.Lock-Screen-Settings.extension
  lockdelay    com.apple.Lock-Screen-Settings.extension
  firewall     com.apple.Network-Settings.extension
  sharing      com.apple.Sharing-Settings.extension
  clock        com.apple.Date-Time-Settings.extension
)
[[ -d $BD_APP ]] && PANE[antivirus]=$BD_APP

card() {  # card <id>: sets title, why, steps
  steps=()
  case $1 in
    macos)
      title="Upgrade macOS"
      why="Older versions of macOS no longer get security fixes, so known holes stay open."
      steps=("$SETTINGS" "Click General, then Software Update" "Install the macOS upgrade it offers. If your Mac is too old to upgrade, ask for help") ;;
    updates)
      title="Install waiting updates"
      why="Updates fix security holes that attackers already know about."
      steps=("Save your work: your Mac may restart" "$SETTINGS" "Click General, then Software Update" "Click Update Now (or Restart Now) and let it finish") ;;
    autoupdate)
      title="Turn on automatic security updates"
      why="Urgent security fixes then install on their own, without you having to remember."
      steps=("$SETTINGS" "Click General, then Software Update" "Click the ⓘ next to Automatic updates" "Turn on \"Check for updates\" and \"Install Security Responses and system files\", then click Done") ;;
    filevault)
      title="Turn on disk encryption (FileVault)"
      why="If your Mac is lost or stolen, nobody can read your files without your password."
      steps=("Plug your Mac into power" "$SETTINGS" "Click Privacy & Security, then scroll down to FileVault" "Click Turn On… and follow the steps. Keep the recovery key somewhere safe, not on this Mac" "Leave it plugged in until encryption finishes, then run this check again") ;;
    password)
      title="Set a login password"
      why="Without one, anyone who picks up your Mac can use it and see your work."
      steps=("$SETTINGS" "Click Users & Groups, then the ⓘ next to your name" "Click Change Password… and choose a strong password") ;;
    autologin)
      title="Turn off automatic login"
      why="Automatic login skips your password, so anyone who opens the lid gets straight in."
      steps=("$SETTINGS" "Click Users & Groups" "Set \"Automatically log in as\" to Off") ;;
    displaysleep)
      title="Make the screen turn off sooner"
      why="Your Mac then locks itself within $MAX_DISPLAY_SLEEP_MIN minutes if you walk away."
      steps=("$SETTINGS" "Click Lock Screen" "Set every \"Turn display off … when inactive\" option to $MAX_DISPLAY_SLEEP_MIN minutes or less") ;;
    lockdelay)
      title="Ask for your password as soon as the screen turns off"
      why="Otherwise someone can wake your Mac and use it without the password."
      steps=("$SETTINGS" "Click Lock Screen" "Set \"Require password after screen saver begins or display is turned off\" to Immediately") ;;
    firewall)
      title="Turn on the firewall"
      why="It blocks other devices on the same network (e.g. café or hotel wifi) from connecting to your Mac."
      steps=("$SETTINGS" "Click Network, then Firewall" "Turn the firewall On") ;;
    antivirus)
      title="Get anti-virus running"
      why="It catches viruses and other harmful software before they can do damage."
      if [[ -n $av_pid ]]; then
        steps=("Open Bitdefender (Endpoint Security for Mac, in Applications) and click Update" "Restart your Mac if it still says it's out of date")
      elif (( company )) && [[ -d $BD_APP ]]; then
        steps=("Open Endpoint Security for Mac from Applications and check it says you're protected" "If it doesn't, restart your Mac and run this check again")
      elif (( company )); then
        steps=("Bitdefender isn't installed: ask for help to install it")
      else
        steps=("Install anti-virus software, e.g. Bitdefender, Microsoft Defender, Sophos or Malwarebytes" "Make sure its real-time protection is on, then run this check again")
      fi ;;
    gatekeeper)
      title="Turn App safety (Gatekeeper) back on"
      why="It warns you before opening apps from unknown developers, which is a common way malware gets in."
      steps=("$SETTINGS" "Click Privacy & Security, then scroll down to Security" "Set \"Allow applications from\" to App Store & Known Developers") ;;
    sip)
      title="Turn System Integrity Protection back on"
      why="It stops harmful software from changing the core parts of macOS."
      steps=("This needs a restart into recovery mode: ask for help") ;;
    clock)
      title="Set the clock automatically"
      why="An accurate clock keeps security logs trustworthy and stops logins failing."
      steps=("$SETTINGS" "Click General, then Date & Time" "Turn on \"Set time and date automatically\"" "If you're offline, connect to the internet and run this check again") ;;
    sharing)
      title="Turn off remote access and sharing"
      why="These let other people connect to your Mac over the network. Keep them off unless you need them."
      steps=("$SETTINGS" "Click General, then Sharing" "Turn off ${(j: and :)on}" "If you need one of these for your work, ask for help so it can be recorded as an exception") ;;
    apps)
      title="Save the installed apps list"
      why="It lets us keep track of the software installed on company Macs."
      steps=("Check you can save files to your Desktop, then run this check again") ;;
  esac
}

# ── Report ───────────────────────────────────────────────────────────────
fails=(); for id in $ids; do (( ok[$id] )) || fails+=$id; done

[[ -t 1 ]] && printf '\e[8;44;120t'   # widen Terminal so rows don't wrap
clear
rule="  ${D}$(printf '─%.0s' {1..112})${X}"
kind=$( (( company )) && print "Company-owned Mac" || print "Contractor Mac")
print ""
print "  ${B}DEVICE SECURITY CHECK${X}   ${B}$(date '+%a %d %b %Y %H:%M:%S %Z')${X}  ${D}$(date -u '+%Y-%m-%dT%H:%M:%SZ')${X}"
print "  $kind · $model · serial ${B}$serial${X} · name $host"
print "  $(id -F) ($USER) · macOS $os_ver ($os_build)"
print $rule

if (( ! ${#fails} )); then
  for id in $ids; do
    printf "  ${G}✔${X}  %-25s ${D}%-40s${X} %s\n" "${label[$id]}" "${evcmd[$id]}" "${evout[$id]}"
  done
  print $rule
  print "  ${G}${B}✔ READY: all ${#ids} checks pass.${X}  Take a screenshot of this whole screen (⌘⇧3) and send it in."
  (( company )) && print "  Send the apps list from your Desktop too: ${apps_file:t}  ${D}sha256 $apps_sha…${X}"
  print "  ${D}Each check is a built-in macOS command (middle column) that anyone can re-run to verify. Check v$VERSION${X}"
  print ""
  exit 0
fi

for id in $ids; do
  if (( ok[$id] )); then
    printf "  ${G}✔${X}  %-26s %s\n" "${label[$id]}" "${plain[$id]}"
  else
    printf "  ${R}✖${X}  ${B}%-26s${X} ${R}%s${X}\n" "${label[$id]}" "${plain[$id]}"
  fi
done
print $rule
print "  ${B}${#fails} thing(s) to fix before this Mac is ready.${X} Each one takes a minute or two:"
typeset -i n=0
for id in $fails; do
  n+=1; card $id
  print ""
  print "  ${B}$n. $title${X}"
  print "     ${D}Why: $why${X}"
  typeset -i s=0
  for st in $steps; do s+=1; print "     $s) $st"; done
done
print ""
print "  When you're done, run this check again. Stuck? Take a screenshot of this screen and ask for help."

# Offer to open the right settings page (reads the keyboard even when piped from curl)
if [[ -t 1 ]] && { exec 3</dev/tty } 2>/dev/null; then
  while true; do
    print -n "\n  Type a number to open that setting for you, or press Enter to finish: "
    read -u 3 -r choice || break
    [[ -z $choice ]] && break
    target=""
    [[ $choice == <-> ]] && (( choice >= 1 && choice <= ${#fails} )) && target=${PANE[${fails[$choice]}]}
    if [[ -z $target ]]; then
      print "  There's no settings page to open for that one. Follow the steps above."
    elif [[ $target == /* ]]; then
      open "$target"
    else
      open "x-apple.systempreferences:$target"
    fi
  done
fi
print ""
exit 1
