??    L      |  e   ?      p  `   q  b   ?  p   5  k   ?  #        6     S     j  )   ?  	   ?  3   ?     ?  ?   	      ?	  ,   ?	  $   ?	     
      
     <
     \
  #   {
  !   ?
     ?
     ?
  %   ?
          3     N     e     t     ?     ?     ?  ?   ?  &   ?     ?     ?     ?  ?     d   ?     S  $   j  u   ?  C     =   I     ?  &   ?  +   ?     ?  )        .  (   H  ?   q  .   -  F   \  "   ?  -   ?     ?  
          2   2  $   e  ,   ?  '   ?  '   ?            +   "     N     c     w          ?     ?     ?  ?  ?  y   Y  n   ?  ~   B  ?   ?  (   K  #   t     ?     ?  0   ?  
     C        U  ?   u  $     4   0  +   e     ?  $   ?  #   ?  "   ?  1     &   L  ,   s  *   ?  $   ?  $   ?  '     #   =     a     w     ?     ?     ?  ?   ?  2   ?  *   ?     "  "   >  ?   a  u   ]     ?     ?  ~     D   ?  N   ?         '   @   5   h       ?   2   ?   +   ?   3   !  ?   R!  @   "  <   R"  #   ?"  8   ?"      ?"     #     #  <   /#  (   l#  @   ?#  *   ?#  /   $     1$     @$  3   T$     ?$     ?$     ?$     ?$  	   ?$  	   ?$     ?$     0   K         1          G   2                  J       )   #          7   .   =              9   &                           E               F   "   +          5       '      ;   4   ?       	       8   
         A   :         !   <   /                         @         I   B   6                     -      %   ,       L      C   D   (            *      >   H   $   3      -                     reset options

  udp/tcp names: [local_port][,[rmt_host][,[rmt_port]]]

   -4,--ipv4             search IPv4 sockets only
  -6,--ipv6             search IPv6 sockets only
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
 Unable to open stat file for pid %d (%s)
 Unknown local port AF %d
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
 running sleeping traced unknown zombie Project-Id-Version: psmisc 22.21-pre2
Report-Msgid-Bugs-To: csmall@enc.com.au
POT-Creation-Date: 2017-06-16 06:42+1000
PO-Revision-Date: 2014-02-02 11:53+0100
Last-Translator: Petr Pisar <petr.pisar@atlas.cz>
Language-Team: Czech <translation-team-cs@lists.sourceforge.net>
Language: cs
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8-bit
X-Bugs: Report translation errors to the Language-Team address.
   -                     konec přepínačů

  Názvy UDP/TCP: [místní_port][,[vzdálený_stroj][,[vzdálený_port]]]

   -4,--ipv4             hledá pouze mezi IPv4 sockety
  -6,--ipv6             hledá pouze mezi IPv6 sockety
   -Z,--context REGVÝR zabije jen proces(y) mající kontext
                      (musí předcházet ostatním argumentům)
   PID       začne na tomto PID; implicitní je 1 (init)
  UŽIVATEL  zobrazí jen stromy, jejichž kořeny náleží tomuto uživateli

 %*s UŽIVATEL    PID PŘÍSTUP PŘÍKAZ
 %s je prázdný (není připojen?)
 %s: Neplatný přepínač %s
 %s: žádný proces nenalezen
 %s: neznámý signál, %s -l vypíše signály.
 (neznámo) /proc není připojen, nelze získat informace o /proc/self/stat.
 Chybný regulární výraz: %s
 Časy CPU
  Tento proces    (uživ systém host blokI/O): %6.2f %6.2f %6.2f %6.2f
  Procesy potomků (uživ systém host):         %6.2f %6.2f %6.2f
 Nelze zjistit schopnosti terminálu
 Paměť pro odpovídající proc nelze alokovat: %s
 Nelze nalézt číslo zařízení socketu.
 Uživatele %s nelze nalézt
 Adresář /proc nelze otevřít: %s
 /proc/net/unix nelze otevřít: %s
 Síťový socket nelze otevřít.
 Soubor s protokoly „%s“ nelze otevřít: %s
 Místní port %s nelze přeložit: %s
 Nelze získat informace (stat(2)) o %s: %s
 O souboru %s nelze získat informace: %s
 Copyright © 2007 Trent Waddington

 Proces %d nebylo možné zabít: %s
 Chyba při připojování se na PID %i
 Neplatný název jmenného prostoru Neplatný přepínač Neplatný formát času Zabít %s(%s%d)? (a/N)  Zabít proces %d? (a/N)  %s(%s%d) zabit signálem %d
 Paměť
  Vvelikost:   %-10s
  RSS:         %-10s 		 Omezení RSS: %s
  Začátek kódu:      %#-10lx		 Konec kódu:  %#-10lx
  Začátek zásobníku: %#-10lx
  Ukazatel na zásobník (ESP): %#10lx  Ukazatel na kód (EIP): %#10lx
 Přepínač jmenného prostoru vyžaduje argument. Žádné kritérium procesu nebylo zadáno Žádný proces nenalezen.
 Žádný uživatel se jménem: %s
 PSmisc je dodáván BEZ ABSOLUTNĚ ŽÁDNÉ ZÁRUKY.
Toto je svobodné programové vybavení, můžete jej šířit podle podmínek
GNU Obecné veřejné licence (GPL).
Podrobnosti v této záležitosti naleznete v souborech pojmenovaných COPYING.
 Výpadky stránek
  Tento proces    (menší větší): %8lu  %8lu
  Procesy potomků (menší větší): %8lu  %8lu
 Uzavřete klávesou Enter
 Proces s PID %d neexistuje.
 ID procesu, skupiny a relace
      ID procesu: %d		 ID rodiče: %d
      ID skupiny: %d		 ID relace: %d
  ID skupiny vl.: %d

 Proces: %-14s		Stav: %c (%s)
  CPU č.:  %-3d		TTY: %s	Vláken: %ld
 Plánování
  Politika %s
  Nice:   %ld 		 Priorita reálného času: %ld %s
 Zaslat signál %s(%s%d) ? (a/N)  Soubor zadaného názvu %s neexistuje.
 Soubor zadaného názvu %s není přípojným bodem.
 Proměnná TERM není nastavena
 Soubor se statistikou PID %d nelze otevřít (%s)
 Neznámá rodina adres %d místního portu
 Použití: killall [PŘEPÍNAČ…] [--] NÁZEV…
 Použití: prtstat [PŘEPÍNAČE] PID…
         prtstat -V
Zobrazí informace o procesu
    -r,--raw       Neopracovaný výstup
    -V,--version   Zobrazí informace o verzi a skončí
 Spolu s přepínači bodů připojení lze použít jen soubory Nelze současně hledat jen v IPv4 a jen v IPv6 socketech. Je třeba zadat alespoň jedno PID. Přepínač -a nelze použít spolu s přepínačem -s. asprintf v print_stat selhala.
 čeká na disk fuser (PSmisc) %s
 killall: %s postrádá záznamy procesů (není připojen?)
 killall: Chybný regulární výraz: %s
 killall: Z procesového souboru „status“ nelze získat UID
 killall: Maximální počet názvů je %d
 killall: částečná shoda %s(%d) se vynechá
 odstránkován peekfd (PSmisc) %s
 proc soubor pro jmenný prostor %s není dostupný
 prtstat (PSmisc) %s
 pstree (PSmisc) %s
 běží spí trasován neznámý zombie 