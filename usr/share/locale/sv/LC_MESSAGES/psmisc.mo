??    Q      ?  m   ,      ?  `   ?  b   B  N   ?  p   ?  k   e  #   ?     ?     	     )	  )   ?	  	   i	  3   s	     ?	  ?   ?	      R
  ,   s
  $   ?
     ?
      ?
     ?
       #   :  !   ^     ?     ?  %   ?     ?     ?          $     3     G     ^     w  ?   ?  &   X          ?     ?  ?   ?  d   ?       $   )  u   N  C   ?  =        F  &   _  +   ?     ?  (   ?  )   ?          /    I     Q  (   ?  ?   ?  .   ?  F   ?  "   ,  -   O     }  
   ?     ?  2   ?  $   ?  ,     '   @  '   h     ?     ?  +   ?     ?     ?                             ?  '  i     |   ?  P      v   Q  ?   ?  &   \     ?     ?     ?  *   ?     ?  A     !   I  ?   k  ,     0   /  &   `     ?  $   ?  #   ?  $   ?  (      $   <      a   "   ?   $   ?       ?      ?      !     #!     2!     F!     ^!     x!  ?   ?!  *   X"  !   ?"     ?"     ?"  ?  ?"  ]   a$     ?$  &   ?$  ~   %  I   ?%  C   ?%     &  !   -&  0   O&     ?&  (   ?&  *   ?&     ?&     
'  :  ('  ?   c+  .   ?+  ?   ,  8   ?,  D   -  '   W-  D   -  $   ?-  
   ?-     ?-  2   .  *   :.  0   e.  $   ?.  0   ?.     ?.     ?.  .   /     ;/     P/     d/     i/     o/     w/     ~/         P   K   ;                  (   E       D   M              8      -   )                 N   6      <   F         O                         5       7   	                 ,         J                     Q              1       2   %      #       G   '             +   C       *   0   H   "      =       &   9   $   :          L   /       !                  
      4   @       ?   I   3   >   .   B   A      -                     reset options

  udp/tcp names: [local_port][,[rmt_host][,[rmt_port]]]

   -4,--ipv4             search IPv4 sockets only
  -6,--ipv6             search IPv6 sockets only
   -Z, --security-context
                      show SELinux security contexts
   -Z,--context REGEXP kill only process(es) having context
                      (must precede other arguments)
   PID    start at this PID; default is 1 (init)
  USER   show only trees rooted at processes of this user

 %*s USER        PID ACCESS COMMAND
 %s is empty (not mounted ?)
 %s: Invalid option %s
 %s: no process found
 %s: unknown signal; %s -l lists signals.
 (unknown) /proc is not mounted, cannot stat /proc/self/stat.
 Bad regular expression: %s
 CPU Times
  This Process    (user system guest blkio): %6.2f %6.2f %6.2f %6.2f
  Child processes (user system guest):       %6.2f %6.2f %6.2f
 Can't get terminal capabilities
 Cannot allocate memory for matched proc: %s
 Cannot find socket's device number.
 Cannot find user %s
 Cannot open /proc directory: %s
 Cannot open /proc/net/unix: %s
 Cannot open a network socket.
 Cannot open protocol file "%s": %s
 Cannot resolve local port %s: %s
 Cannot stat %s: %s
 Cannot stat file %s: %s
 Copyright (C) 2007 Trent Waddington

 Could not kill process %d: %s
 Error attaching to pid %i
 Invalid namespace name Invalid option Invalid time format Kill %s(%s%d) ? (y/N)  Kill process %d ? (y/N)  Killed %s(%s%d) with signal %d
 Memory
  Vsize:       %-10s
  RSS:         %-10s 		 RSS Limit: %s
  Code Start:  %#-10lx		 Code Stop:  %#-10lx
  Stack Start: %#-10lx
  Stack Pointer (ESP): %#10lx	 Inst Pointer (EIP): %#10lx
 Namespace option requires an argument. No process specification given No processes found.
 No such user name: %s
 PSmisc comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it under
the terms of the GNU General Public License.
For more information about these matters, see the files named COPYING.
 Page Faults
  This Process    (minor major): %8lu  %8lu
  Child Processes (minor major): %8lu  %8lu
 Press return to close
 Process with pid %d does not exist.
 Process, Group and Session IDs
  Process ID: %d		  Parent ID: %d
    Group ID: %d		 Session ID: %d
  T Group ID: %d

 Process: %-14s		State: %c (%s)
  CPU#:  %-3d		TTY: %s	Threads: %ld
 Scheduling
  Policy: %s
  Nice:   %ld 		 RT Priority: %ld %s
 Signal %s(%s%d) ? (y/N)  Specified filename %s does not exist.
 Specified filename %s is not a mountpoint.
 TERM is not set
 Unable to allocate memory for proc_info
 Unable to open stat file for pid %d (%s)
 Unable to scan stat file Unknown local port AF %d
 Usage: fuser [-fIMuvw] [-a|-s] [-4|-6] [-c|-m|-n SPACE]
             [-k [-i] [-SIGNAL]] NAME...
       fuser -l
       fuser -V
Show which processes use the named files, sockets, or filesystems.

  -a,--all              display unused files too
  -i,--interactive      ask before killing (ignored without -k)
  -I,--inode            use always inodes to compare files
  -k,--kill             kill processes accessing the named file
  -l,--list-signals     list available signal names
  -m,--mount            show all processes using the named filesystems or
                        block device
  -M,--ismountpoint     fulfill request only if NAME is a mount point
  -n,--namespace SPACE  search in this name space (file, udp, or tcp)
  -s,--silent           silent operation
  -SIGNAL               send this signal instead of SIGKILL
  -u,--user             display user IDs
  -v,--verbose          verbose output
  -w,--writeonly        kill only processes with write access
  -V,--version          display version information
 Usage: killall [ -Z CONTEXT ] [ -u USER ] [ -y TIME ] [ -o TIME ] [ -eIgiqrvw ]
               [ -s SIGNAL | -SIGNAL ] NAME...
 Usage: killall [OPTION]... [--] NAME...
 Usage: prtstat [options] PID ...
       prtstat -V
Print information about a process
    -r,--raw       Raw display of information
    -V,--version   Display version information and exit
 You can only use files with mountpoint options You cannot search for only IPv4 and only IPv6 sockets at the same time You must provide at least one PID. all option cannot be used with silent option. asprintf in print_stat failed.
 disk sleep fuser (PSmisc) %s
 killall: %s lacks process entries (not mounted ?)
 killall: Bad regular expression: %s
 killall: Cannot get UID from process status
 killall: Maximum number of names is %d
 killall: skipping partial match %s(%d)
 paging peekfd (PSmisc) %s
 procfs file for %s namespace not available
 prtstat (PSmisc) %s
 pstree (PSmisc) %s
 running sleeping traced unknown zombie Project-Id-Version: psmisc 23.0-rc1
Report-Msgid-Bugs-To: csmall@enc.com.au
POT-Creation-Date: 2017-06-16 06:42+1000
PO-Revision-Date: 2017-01-11 22:41+0100
Last-Translator: Sebastian Rasmussen <sebras@gmail.com>
Language-Team: Swedish <tp-sv@listor.tp-sv.se>
Language: sv
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
X-Bugs: Report translation errors to the Language-Team address.
Plural-Forms: nplurals=2; plural=(n != 1);
X-Generator: Poedit 1.8.11
   -                     nollställ flaggor

  udp/tcp-namn: [lokal_port][,[fjärrvärd][,[fjärrport]]]

   -4,--ipv4             sök endast bland IPv4-uttag (socket)
  -6,--ipv6             sök endast bland IPv6-uttag (socket)
   -Z, --security-context
                      visa SELinux-säkerhetskontexter
   -Z,--context REGEXP döda endast process(er) som har kontext
                      (måste föregå andra argument)
   PID    starta vid denna PID; standardvärde är 1 (init)
  ANVÄNDARE   visa endast träd med denna användares
              processer som rot

 %*s ANVÄNDARE   PID ÅTKOMS KOMMANDO
 %s är tom (inte monterad?)
 %s: Ogiltig flagga %s
 %s: ingen process hittades
 %s: okänd signal; %s -l listar signaler.
 (okänd) /proc är inte monterad, kan inte ta status på /proc/self/stat.
 Felaktigt reguljärt uttryck: %s
 CPU-tider
  Denna process (användare system gäst blkio): %6.2f %6.2f %6.2f %6.2f
  Barnprocesser (användare system gäst):       %6.2f %6.2f %6.2f
 Kan inte ta reda på terminalens förmågor
 Kan inte allokera minne för matchande proc: %s
 Kan inte hitta uttagets enhetsnummer.
 Kan inte hitta användare %s
 Kan inte öppna katalogen /proc: %s
 Kan inte öppna /proc/net/unix: %s
 Kan inte öppna ett nätverksuttag.
 Kan inte öppna protokollfilen "%s": %s
 Kan inte slå upp lokal port %s: %s
 Kan inte ta status på %s: %s
 Kan inte ta status på fil %s: %s
 Copyright © 2007 Trent Waddington

 Kunde inte döda process %d: %s
 Fel vid koppling till pid %i
 Ogiltigt namn för namnrymd Ogiltig flagga Ogiltigt tidsformat Döda %s(%s%d) ? (y/N)  Döda process %d ? (y/N)  Dödade %s(%s%d) med signal %d
 Minne
  V-storlek:  %-10s
  RSS:        %-10s 		 RSS-begränsning: %s
  Kodstart:   %#-10lx		 Kodslut:  %#-10lx
  Stackstart: %#-10lx
  Stackpekare (ESP): %#10lx	 Instr.-pekare (EIP): %#10lx
 Flagga för namnrymd kräver ett argument. Ingen processpecifikation angiven Inga processer hittades.
 Ingen sådan användare: %s
 PSmisc kommer med ABSOLUT INGEN GARANTI.
Detta är fri programvara och du är välkommen att distribuera den under
villkoren för GNU General Public License.
För mer information om dessa villkor, se filerna kallade COPYING.
Följande text är en informell översättning som enbart tillhandahålls
i informativt syfte. För alla juridiska tolkningar gäller den engelska originaltexten.
 Sidfel
  Denna Process (lägre övre): %8lu  %8lu
  Barnprocesser (lägre övre): %8lu  %8lu
 Tryck Retur för att stänga
 Någon process med pid %d finns inte.
 Process-, Grupp- och Sessions-ID
  Process-ID: %d		 Överordnat ID: %d
    Group-ID: %d		   Sessions-ID: %d
  T Group-ID: %d

 Process: %-14s		Tillstånd: %c (%s)
  Proc.:  %-3d		TTY: %s	Trådar: %ld
 Schemaläggning
  Policy: %s
  Nice:   %ld 		 RT-prioritet: %ld %s
 Signalera %s(%s%d) ? (y/N)  Angivna filnamnet %s finns inte.
 Angivet filnamn %s är inte en monteringspunkt.
 TERM är inte inställd
 Kan inte allokera minne för proc_info

 Kan inte öppna stat-fil för pid %d (%s)
 Kan inte genomsöka stat-fil Okänd AF %d för lokal port
 Användning: fuser [-fIMuvw] [-a|-s] [-4|-6] [-c|-m|-n RYMD]
             [-k [-i] [-SIGNAL]] NAMN…
       fuser -l
       fuser -V
Visa vilka processer som använder namngivna filer, uttag eller filsystem.

  -a,--all              visa även filer som inte används
  -i,--interactive      fråga innan processen dödas (ignoreras utan -k)
  -I,--inode            använd alltid inoder för att jämföra filer
  -k,--kill             döda processer som använder namngiven fil
  -l,--list-signals     lista tillgängliga signalnamn
  -m,--mount            visa alla processer som använder namngivna filsystem eller blockenheter
  -M,--ismountpoint     genomför begäran endast om NAMN är en monteringspunkt
  -n,--namespace RYMD   sök i denna namnrymd (fil, udp, tcp)
  -s,--silent           tyst körning
  -SIGNAL               skicka denna signal istället för SIGKILL
  -u,--user             visa användar-ID
  -v,--verbose          informativ utskrift
  -w,--writeonly        döda bara processer med skrivrättighet
  -V,--version          visa versionsinformation
 Användning: killall [-Z KONTEXT] [-u ANVÄNDARE] [-y TID] [ -o TID ] [ -eIgiqrvw ]
               [ -s SIGNAL | -SIGNAL ] NAMN...
 Användning: killall [FLAGGA]… [--] NAMN…
 Användning: prtstat [flaggor] PID …
       prtstat -V
Skriv ut information om en process
    -r,--raw       Rå visning av information
    -V,--version   Visa versionsinformation och avsluta
 Du kan endast använda filer med monteringspunktsflaggor Du kan inte söka efter endast IPv4- och endast IPv6-uttag samtidigt Du måste tillhandahålla minst en PID. flagga för alla, -m,  kan inte användas med flaggan för tyst, -s. asprintf i print_stat misslyckades.
 disk sover fuser (PSmisc) %s
 killall: %s saknar processposter (inte monterad?)
 killall: Felaktigt reguljärt uttryck: %s
 killall: Kan inte hämta UID från processtatus
 killall: Maximalt antal namn är %d
 killall: hoppar över partiell matchning %s(%d)
 sidväxling peekfd (PSmisc) %s
 procfs-fil för %s-namnrymd inte tillgänglig
 prtstat (PSmisc) %s
 pstree (PSmisc) %s
 kör sover spårad okänd zombie 