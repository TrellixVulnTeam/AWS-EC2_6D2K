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
          2   2  $   e  ,   ?  '   ?  '   ?            +   "     N     c     w          ?     ?     ?  ?  ?  n   D  ^   ?  t     ?   ?  $        5     Q     l  =   ?     ?  @   ?  $     ?   ;  3   ?  @     9   L      ?  *   ?  &   ?  &   ?  2      -   S      ?  &   ?  %   ?  )   ?           :     V     i     ?      ?  "   ?  ?   ?  ,   ?  #   ?     ?  "     ?   2          ?  #   ?  {   ?  D   B  =   ?     ?      ?  +   ?     +   6   B      y   '   ?   ?   ?   1   ?!  I   ?!     ?!  4   "  %   T"     z"     ?"  7   ?"  -   ?"  =   #  )   E#  1   o#     ?#     ?#  /   ?#     ?#     $     $  	   #$  	   -$     7$     C$     0   K         1          G   2                  J       )   #          7   .   =              9   &                           E               F   "   +          5       '      ;   4   ?       	       8   
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
PO-Revision-Date: 2015-08-05 12:17+0100
Last-Translator: Marco Colombo <m.colombo@ed.ac.uk>
Language-Team: Italian <tp@lists.linux.it>
Language: it
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
X-Bugs: Report translation errors to the Language-Team address.
   -                     reimposta le opzioni

  nomi udp/tcp: [porta locale][,[host remoto][,[porta remota]]]
   -4,--ipv4             cerca solo socket IPv4
  -6,--ipv6             cerca solo socket IPv6
   -Z,--context REGEXP termina solo i processi aventi context
                      (deve precedere altri argomenti)
     PID       comincia dal pid indicato, predefinito 1 (init)
    UTENTE    mostra solo gli alberi con radice nei processi dell'utente

 %*s UTENTE      PID ACCESSO COMANDO
 %s è vuoto (non montato?)
 %s: Opzione %s non valida
 %s: nessun processo trovato
 %s: segnale sconosciuto; usare %s -l per elencare i segnali.
 (sconosciuto) /proc non è montato, impossibile fare stat di /proc/self/stat.
 Espressione regolare non valida: %s
 Utilizzo temporale CPU
  Questo processo (user system guest blkio): %6.2f %6.2f %6.2f %6.2f
  Processi figli  (user system guest):       %6.2f %6.2f %6.2f
 Impossibile determinare le capacità del terminale
 Impossibile allocare memoria per il processo corrispondente: %s
 Impossibile trovare il numero di dispositivo del socket.
 Impossibile trovare l'utente %s
 Impossibile aprire la directory /proc: %s
 Impossibile aprire /proc/net/unix: %s
 Impossibile aprire un socket di rete.
 Impossibile aprire il file di protocollo "%s": %s
 Impossibile risolvere la porta locale %s: %s
 Impossibile fare stat di %s: %s
 Impossibile fare stat del file %s: %s
 Copyright (C) 2007 Trent Waddington

 Impossibile terminare il processo %d: %s
 Errore nel collegarsi al pid %i
 Nome di contesto non valido Opzione non valida Formato orario non valido Terminare %s(%s%d)? (s/N)  Terminare il processo %d? (s/N)  Terminato %s(%s%d) con segnale %d
 Memoria
  Vsize:       %-10s
  RSS:         %-10s 		 RSS Limit: %s
  Code Start:  %#-10lx		 Code Stop:  %#-10lx
  Stack Start: %#-10lx
  Stack Pointer (ESP): %#10lx	 Inst Pointer (EIP): %#10lx
 L'opzione di contesto richiede un argomento. Nessun tipo di processo specificato Nessun processo trovato.
 Questo nome utente non esiste: %s
 PSmisc è distribuito senza ALCUNA GARANZIA.
Questo è software libero, ed è possibile redistribuirlo secondo i termini
della GNU General Public License.
Si consulti il file COPYING per ulteriori informazioni.
 Errori di pagina (page faults)
  Questo processo (minore maggiore): %8lu  %8lu
  Processi figli  (minore maggiore): %8lu  %8lu
 Premere Invio per chiudere
 Il processo con pid %d non esiste.
 ID di processo, gruppo e sessione
  ID Processo: %d		  ID Parent: %d
    ID Gruppo: %d		ID Sessione: %d
  ID Gruppo T: %d

 Processo: %-14s		Stato: %c (%s)
  CPU#:  %-3d		TTY: %s	Threads: %ld
 Scheduling
  Policy: %s
  Nice:   %ld 		 RT Priority: %ld %s
 Segnale %s(%s%d)? (s/N)  Il file indicato %s non esiste.
 Il file indicato %s non è un mount point.
 TERM non è impostato
 Impossibile aprire il file di stat per il pid %d (%s)
 Porta locale AF %d sconosciuta
 Uso: killall [OPZIONE]... [--] NOME...
 Uso: prtstat [opzioni] PID ...
     prtstat -V
Stampa informazioni su un processo
    -r,--raw       Mostra informazioni grezze
    -V,--version   Mostra le informazioni sulla versione ed esce
 Con l'opzione -m si possono specificare solo file Impossibile cercare solo socket IPv4 e solo socket IPv6 allo stesso tempo Occorre indicare almeno un PID. L'opzione -a non può essere usata con l'opzione -s. asprintf in print_stat non riuscito.
 in attesa del disco fuser (PSmisc) %s
 killall: %s non ha una voce di processo (non montato?)
 killall: Espressione regolare non valida: %s
 killall: Impossibile ottenere l'UID dallo stato del processo
 killall: Il massimo numero di nomi è %d
 killall: ignorata corrispondenza parziale %s(%d)
 paging peekfd (PSmisc) %s
 file procfs per il contesto %s non disponibile
 prtstat (PSmisc) %s
 pstree (PSmisc) %s
 in esecuzione in attesa tracciato sconosciuto zombie 