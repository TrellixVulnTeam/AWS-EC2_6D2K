??    Q      ?  m   ,      ?  `   ?  b   B  N   ?  p   ?  k   e  #   ?     ?     	     )	  )   ?	  	   i	  3   s	     ?	  ?   ?	      R
  ,   s
  $   ?
     ?
      ?
     ?
       #   :  !   ^     ?     ?  %   ?     ?     ?          $     3     G     ^     w  ?   ?  &   X          ?     ?  ?   ?  d   ?       $   )  u   N  C   ?  =        F  &   _  +   ?     ?  (   ?  )   ?          /    I     Q  (   ?  ?   ?  .   ?  F   ?  "   ,  -   O     }  
   ?     ?  2   ?  $   ?  ,     '   @  '   h     ?     ?  +   ?     ?     ?                             Z  '  t   ?  l   ?  S   d  ?   ?     <  $   ?     ?             -   5     c  C   o     ?  ?   ?  &   k  7   ?  *   ?     ?  &      $   ;   $   `   1   ?   %   ?   $   ?   0   !  $   3!      X!      y!  )   ?!     ?!     ?!     ?!     "     )"  ?   H"  5   %#  #   [#     #     ?#  ?   ?#  ?   ?$  &   %     @%  x   `%  B   ?%  @   &     ]&  !   v&  D   ?&     ?&  (   ?&  9   '  )   V'     ?'  z  ?'  ?   ,  )   ?,  ?   ?,  H   ?-  D   ?-     .  >   6.  "   u.  
   ?.     ?.  1   ?.  (   ?.  .   /  #   @/  3   d/     ?/     ?/  >   ?/     ?/     0     !0     *0     60  	   >0     H0         P   K   ;                  (   E       D   M              8      -   )                 N   6      <   F         O                         5       7   	                 ,         J                     Q              1       2   %      #       G   '             +   C       *   0   H   "      =       &   9   $   :          L   /       !                  
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
 running sleeping traced unknown zombie Project-Id-Version: psmisc-23.0-rc1
Report-Msgid-Bugs-To: csmall@enc.com.au
POT-Creation-Date: 2017-06-16 06:42+1000
PO-Revision-Date: 2016-12-15 16:53-0800
Last-Translator: Božidar Putanec <bozidarp@yahoo.com>
Language-Team: Croatian <lokalizacija@linux.hr>
Language: hr
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
X-Bugs: Report translation errors to the Language-Team address.
Plural-Forms: nplurals=3; plural=(n%10==1 && n%100!=11 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2);
X-Generator: Poedit 1.8.7.1
X-Poedit-SourceCharset: UTF-8
   -                     resetiraj opcije

  udp/tcp imena: [lokalni_port][,[udaljeno_računalo][,[udaljeni_port]]]

   -4,--ipv4             pretraži samo IPv4 utičnice
  -6,--ipv6             pretraži samo IPv6 utičnice
   -Z, --security-context
                      pokaži SELinux sigurnosni kontekst
   -Z,--context REGEXP prekini samo procese s odgovarajućim kontekstom
                      (mora prethoditi ostalim argumentima)
   PID       započni s ovim PID-om; zadan je 1 (init)
  KORISNIK  prikaži samo stablo s korijenom u procesima ovog KORISNIKA

 %*s KORISNIK    PID PRISTUP NAREDBA
 %s je prazan (nije montiran?)
 %s: Neispravna opcija %s
 %s: proces nije pronađen
 %s: nepoznat signal; %s -l ispisuje signale.
 (nepoznato) /proc nije montiran, ne mogu izvršiti ‘stat’ /proc/self/stat.
 Neispravan regularni izraz: %s
 CPU vremena
  Ovaj proces   (korisnik sustav gost blkio): %6.2f %6.2f %6.2f %6.2f
  Potomački procesi (korisnik sustav gost):       %6.2f %6.2f %6.2f
 Ne mogu otkriti mogućnosti terminala
 Ne mogu alocirati memoriju za odgovarajući proces: %s
 Ne mogu pronaći broj uređaja utičnice.
 Ne mogu pronaći korisnika %s
 Ne mogu otvoriti direktorij /proc: %s
 Ne mogu otvoriti /proc/net/unix: %s
 Ne mogu otvoriti mrežnu utičnicu.
 Ne mogu otvoriti datoteku protokola „%s“: %s
 Ne mogu odrediti lokalni port %s: %s
 Ne mogu izvršiti ‘stat’ %s: %s
 Ne mogu izvršiti ‘stat’ na datoteci %s: %s
 Copyright © 2007 Trent Waddington

 Ne mogu prekinuti proces %d: %s
 Greška pridruživanja pid-u %i
 Neispravno ime prostora imena (namespace) Neispravna opcija Neispravan format vremena Prekinuti %s(%s%d) ? (d/N)  Prekinuti proces %d ? (d/N)  Prekinut %s(%s%d) signalom %d
 Memorija
  Vsize:       %-10s
  RSS:         %-10s 		 RSS granična vrijednost: %s
  Code Start:  %#-10lx		 Konac koda:  %#-10lx
  Stack Start: %#-10lx
  Stack Pointer (ESP): %#10lx	 Pokazivač instrukcije (EIP): %#10lx
 Opcija prostora imena (namespace) zahtijeva argument. Nije navedena specifikacija procesa Nijedan proces nije pronađen.
 Nema takvog korisnika: %s
 Za PSmisc NEMA APSOLUTNO NIKAKVIH JAMSTVA.
Ovo je slobodan softver: slobodno ga mijenjajte i dijelite
pod uvjetima opisanim u GNU General Public License.
Dodatne obavijesti o licenciji potražite u datoteci COPYING.
 Page Faults (pogreška memorijske stranice)
  Ovaj proces    (minor major): %8lu  %8lu
  Potomački proces (minor major): %8lu  %8lu
 Pritisnite return/enter za zatvaranje
 Proces s pid-om %d ne postoji.
  ID-ovi procesa, grupe i sesije
  Proces ID: %d		  Predak(ov) ID: %d
    Grup ID: %d		 Sesijski ID: %d
  T Grup ID: %d

 Proces: %-14s		Stanje: %c (%s)
  CPU#:  %-3d		TTY: %s	Dretve: %ld
 Planiranje
  Pravilnik: %s
  Nice:   %ld 		 RT Priority: %ld %s
 Signal %s(%s%d) ? (d/N)  Navedena datoteka %s ne postoji.
 Navedeni naziv (datoteke) %s nije točka za montiranje (mountpoint)
 TERM nije postavljen
 Ne mogu alocirati memoriju za proc_info
 Nije moguće otvoriti ‘stat’ datoteku za pid %d (%s)
 Nije moguće otvoriti ‘stat’ datoteku Nepoznati lokalni port AF %d
 Uporaba: fuser [-fMuvw] [-a|-s] [-4|-6] [-c|-m|-n PROSTOR]
               [-k [-i] [-SIGNAL]] IME...
         fuser -l
         fuser -V
Prikaži koji procesi koriste navedene datoteke, utičnice ili datotečne sustave.

  -a,--all              prikaži i nekorištene datoteke
  -i,--interactive      pitaj prije prekidanja (zanemareno bez -k)
  -I,--inode            uvijek rabi inodes za usporedbu datoteka
  -k,--kill             prekini procese koji pristupaju navedenoj datoteci
  -l,--list-signals     ispiši imena dostupnih signala
  -m,--mount            prikaži sve procese koji koriste navedene
                        datotečne sustave ili blokovske uređaje
  -M,--ismountpoint     izvrši zahtjev samo ako je IME točka montiranja
  -n,--namespace=PROSTOR  traži u ovom prostoru imena (file, udp ili tcp)
  -s,--silent           tihi rad (bez ispisa)
  -SIGNAL               pošalji ovaj signal umjesto SIGKILL
  -u,--user             prikaži korisničke oznake (ID)
  -v,--verbose          opširan ispis
  -w,--writeonly        prekini samo procese s dozvolom pisanja
  -V,--version          prikaži informacije o inačici
 Uporaba: killall [-Z KONTEKST] [-u KORISNIK] [ -y TIME ] [ -o TIME ] [ -eIgiqrvw ]
               [ -s -SIGNAL | -SIGNAL] IME...
 Uporaba: killall [OPCIJA]... [--] IME...
 Uporaba: prtstat [opcije] PID ...
         prtstat -V
Ispiši informacije o procesu
    -r,--raw       Neobrađeni prikaz informacija
    -V,--version   Prikaži informacije o inačici i izađi
 Smijete koristiti samo datoteke uz opcije točke montiranja (mountpoint) Ne možete istovremeno pretraživati samo IPv4 i samo IPv6 utičnice Morate navesti barem jedan PID. opcija ‘all’ ne može se koristiti uz opciju ‘silent’. asprintf u print_stat nije uspio.
 disk spava fuser (PSmisc) %s
 killall: %s nema zapise procesa (nije montiran?)
 killall: Neispravan regularni izraz: %s
 killall: Ne mogu dobiti UID iz stanja procesa
 killall: Najveći broj imena je %d
 killall: preskačem djelomično podudaranje %s(%d)
 straničenje peekfd (PSmisc) %s
 procfs datoteka za %s prostor imena (namespace) nije dostupna
 prtstat (PSmisc) %s
 pstree (PSmisc) %s
 pokrenut u mirovanju praćen nepoznato zombi 