??    g      T  ?   ?      ?     ?  ?   ?     h	  (   	  -   ?	  <   ?	     
     -
     G
  9   f
  "   ?
  $   ?
  %   ?
       +   *  (   V  ?        2     J     h     w     ?     ?  
   ?  4   ?     ?  6        >  &   P  "   w     ?     ?     ?  B   ?  3     &   <  /   c     ?  -   ?     ?  *   ?  (   ?  L   !  M   n  )   ?  .   ?  =        S     p     ?     ?  ;   ?     ?          !  #   9  1   ]  I   ?  $   ?  &   ?  ,   %     R     k     ?  ;   ?     ?                 7     X     o     ?     ?  !   ?  
   ?  '   ?  '     8   ?      x      ?     ?     ?  A   ?  9        =  !   W     y     ?     ?  &   ?  `   ?     &  #   A     e     ?  0   ?  ,   ?     ?  >        O     d     u  ?  ?     2  ?   4  (   ?     $  .   7  <   f     ?     ?     ?  :   ?  "   1  $   T  %   y     ?  /   ?  ,   ?  ?        ?      ?               (     >  
   N  4   Y     ?  7   ?     ?  +   ?  %        8     A  $   I  O   n  =   ?  3   ?  -   0     ^  6   a     ?  *   ?  %   ?  Y   ?  Z   K   5   ?   8   ?   C   !  +   Y!     ?!     ?!     ?!  <   ?!     
"  &   )"     P"  ,   o"  0   ?"  I   ?"  1   #  D   I#  A   ?#     ?#  0   ?#  (   $  D   E$  ,   ?$  !   ?$     ?$  '   ?$     %  #   8%     \%  %   z%  %   ?%     ?%  3   ?%  6   &  J   =&  (   ?&  "   ?&     ?&     ?&  Q   ?&  A   -'     o'  $   ?'     ?'     ?'     ?'  &   ?'  m   (     v(  '   ?(     ?(     ?(  0   ?(  +   ))     U)  >   m)     ?)     ?)     ?)                <   C      =                F   W   0      .       6   b       U      '      !       \   O   7       5       `          9   ]          I   e   Z         J       
       	       V   ;       K      R   1   (      *   H   D      A       :       ?   3      2   Y      a   c   E      /   %           )   @              _   "               G   4                        B   >           N   S   +   8   M          #   L   X   f                        T          ^       d   &   -       Q   g   ,   [      P   $    
 
Note: This output shows SysV services only and does not include native
      systemd services. SysV configuration data might be overridden by native
      systemd configuration.

 
error reading choice
                     [--family <family>]
                     [--initscript <service>]
                 --altdir <directory> --admindir <directory>
          %s --add <name>
          %s --del <name>
          %s --override <name>
          %s [--level <levels>] [--type <type>] <name> %s
        alternatives --auto <name>
        alternatives --config <name>
        alternatives --display <name>
        alternatives --list
        alternatives --remove <name> <path>
        alternatives --set <name> <path>
       If you want to list systemd services use 'systemctl list-unit-files'.
      To see services enabled on particular target use
      'systemctl list-dependencies [target]'.

   Selection    Command
  link currently points to %s
  slave %s: %s
 %s - status is auto.
 %s - status is manual.
 %s already exists
 %s empty!
 %s has not been configured as an alternative for %s
 %s version %s
 %s version %s - Copyright (C) 1997-2000 Red Hat, Inc.
 (would remove %s
 --family can't contain the symbol '@'
 --type must be 'sysv' or 'xinetd'
 Back Cancel Current `best' version is %s.
 Enter to keep the current selection[+], or type selection number:  Failed to forward service request to systemctl: %m
 No services may be managed by ntsysv!
 Note: Forwarding request to 'systemctl %s %s'.
 Ok Press <F1> for more information on a service. Services There are %d programs which provide '%s'.
 There is %d program that provides '%s'.
 This may be freely redistributed under the terms of the GNU Public License.
 This may be freely redistributed under the terms of the GNU Public License.

 Unable to set selinux context for %s: %s
 What services should be automatically started? You do not have enough privileges to perform this operation.
 You must be root to run %s.
 admindir %s invalid
 altdir %s invalid
 alternatives version %s
 alternatives version %s - Copyright (C) 2001 Red Hat, Inc.
 bad argument to --levels
 bad mode on line 1 of %s
 bad primary link in %s
 cannot determine current run level
 closing '@' missing or the family is empty in %s
 common options: --verbose --test --help --usage --version --keep-missing
 error reading from directory %s: %s
 error reading info for service %s: %s
 error reading information on service %s: %s
 failed to create %s: %s
 failed to glob pattern %s: %s
 failed to link %s -> %s: %s
 failed to link %s -> %s: %s exists and it is not a symlink
 failed to make symlink %s: %s
 failed to open %s/init.d: %s
 failed to open %s: %s
 failed to open directory %s: %s
 failed to read %s: %s
 failed to read link %s: %s
 failed to remove %s: %s
 failed to remove link %s: %s
 failed to replace %s with %s: %s
 family %s  link %s incorrect for slave %s (%s %s)
 link changed -- setting mode to manual
 link points to no alternative -- setting mode to manual
 missing path for slave %s in %s
 numeric priority expected in %s
 off on only one of --list, --add, --del, or --override may be specified
 only one runlevel may be specified for a chkconfig query
 path %s unexpected in %s
 path to alternate expected in %s
 priority %d
 reading %s
 running %s
 service %s does not support chkconfig
 service %s supports chkconfig, but is not referenced in any runlevel (run 'chkconfig --add %s')
 slave path expected in %s
 the primary link for %s must be %s
 unexpected end of file in %s
 unexpected line in %s: %s
 usage:   %s <enable|disable|is-enabled> [name] 
 usage:   %s [--list] [--type <type>] [name]
 usage:   %s [name]
 usage: alternatives --install <link> <name> <path> <priority>
 would link %s -> %s
 would remove %s
 xinetd based services:
 Project-Id-Version: PACKAGE VERSION
Report-Msgid-Bugs-To: 
POT-Creation-Date: 2017-07-25 13:31+0200
PO-Revision-Date: 2017-10-26 10:30+0000
Last-Translator: Elena Metelli <byruit@gmail.com>
Language-Team: Italian <trans-it@lists.fedoraproject.org>
Language: it
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Plural-Forms: nplurals=2; plural=(n != 1);
X-Generator: Zanata 4.6.2
 
 
Nota: Questo output mostra i servizi SysV solo e non iclude i servizi nativi.
      servizi systemd. Dati di configurazione SysV posso essere sovrascritti dai nativi
      configurazione systemd.

 
errore durante la lettura della scelta
 --family <family>
                     [--initscript <servizio>]
                 --altdir <directory> --admindir <directory>
          %s --add <nome>
          %s --del <nome>
          %s --override <nome>
          %s [--level <livelli>] [--type <tipo>] <nome> %s
        alternatives --auto <nome>
        alternatives --config <nome>
        alternatives --display <nome>
 alternatives --list
        alternatives --remove <nome> <percorso>
        alternatives --set <nome> <percorso>
 Se desideri elencare i servizi systemd usa 'systemctl list-unit-files'.⏎ Per visualizzare i servizi abilitati in un target particolare usa ⏎ 'systemctl list-dependencies [target]'. 

   Selezione    Comando
  il link attualmente punta a %s
  slave %s: %s
 %s - stato: auto.
 %s - stato: manuale.
 %s esiste già
 %s vuoto!
 %s non è stato configurato come alternativa per %s
 %s versione %s
 %s versione %s - Copyright (C) 1997-2000 Red Hat, Inc.
 (rimuoverà %s
 --family non può contenere il simbolo '@'
 --type deve essere 'sysv' o 'xinetd'
 Indietro Annulla La migliore versione attuale è %s.
 Invio per mantenere l'attuale selezione[+], o inserire il numero di selezione:  Fallita la richiesta di inoltro del servizio a systemctl: %m
 I servizi potrebbero non essere gestiti da ntsysv!
 Nota: Inoltro richiesta a 'systemctl %s %s'.
 Ok Premere <F1> per maggiori informazioni su un servizio. Servizi Ci sono %d programmi che forniscono '%s'.
 C'è %d programma che fornisce '%s'.
 Questo software è liberamente distribuibile secondo i termini della GNU Public License.
 Questo software è liberamente distribuibile secondo i termini della GNU Public License.

 Impossibile impostare il contesto SELinux per %s: %s
 Quale servizi dovrebbero essere avviati automaticamente? Non si hanno privilegi sufficienti per eseguire questa operazione.
 E' necessario essere root per eseguire %s.
 admindir %s non valida
 altdir %s non valida
 alternatives versione %s
 alternatives versione %s - Copyright (C) 2001 Red Hat, Inc.
 argomento errato per --levels
 modalità difettosa alla riga 1 di %s
 link primario difettoso in %s
 impossibile determinare il runlevel attuale
 '@' di chiusura mancante o famiglia vuota in %s
 opzioni comuni: --verbose --test --help --usage --version --keep-missing
 errore durante la lettura dalla directory %s: %s
 errore durante la lettura delle informazioni per il servizio %s: %s
 errore durante la lettura delle informazioni sul servizio %s: %s
 impossibile creare %s: %s
 impossibile eseguire il glob del pattern %s: %s
 impossibile creare il link %s -> %s: %s
 impossibile collegare %s ->%s: %s esiste e non è un link simbolico
 impossibile creare il link simbolico %s: %s
 impossibile aprire %s/init.d: %s
 impossibile aprire %s: %s
 impossibile aprire la directory %s: %s
 impossibile leggere %s: %s
 impossibile leggere il link %s: %s
 impossibile rimuovere %s: %s
 impossibile rimuovere il link %s: %s
 impossibile sostituire %s con %s: %s
 famiglia %s il link %s non è corretto per lo slave %s (%s %s)
 il link è cambiato -- modalità impostata su manuale
 il link non punta ad alcuna alternativa -- modalità impostata su manuale
 percorso mancante per lo slave %s in %s
 priorità numerica prevista in %s
 off on può essere specificata solo una delle opzioni --list, --add, --del o --override
 può essere specificato un solo runlevel per una query chkconfig
 percorso %s imprevisto in %s
 percorso alternativo previsto in %s
 priorità %d
 lettura di %s
 esecuzione di %s
 il servizio %s non supporta chkconfig
 il servizio %s supporta chkconfig, ma non è referenziato in nessun runlevel (eseguire 'chkconfig --add %s')
 percorso slave previsto in %s
 il link primario per %s deve essere %s
 fine del file imprevista in %s
 riga imprevista in %s: %s
 utilizzo: %s <enable|disable|is-enabled> [nome]
 uso:   %s [--list] [--type·<type>] [nome]
 utilizzo: %s [nome]⏎
 uso:   alternatives --install <link> <name> <path> <priority>
 creerà un link %s -> %s
 eliminerà %s
 servizi basati su xinetd:
 