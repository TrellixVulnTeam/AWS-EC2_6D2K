??    g      T  ?   ?      ?     ?  ?   ?     h	  (   	  -   ?	  <   ?	     
     -
     G
  9   f
  "   ?
  $   ?
  %   ?
       +   *  (   V  ?        2     J     h     w     ?     ?  
   ?  4   ?     ?  6        >  &   P  "   w     ?     ?     ?  B   ?  3     &   <  /   c     ?  -   ?     ?  *   ?  (   ?  L   !  M   n  )   ?  .   ?  =        S     p     ?     ?  ;   ?     ?          !  #   9  1   ]  I   ?  $   ?  &   ?  ,   %     R     k     ?  ;   ?     ?                 7     X     o     ?     ?  !   ?  
   ?  '   ?  '     8   ?      x      ?     ?     ?  A   ?  9        =  !   W     y     ?     ?  &   ?  `   ?     &  #   A     e     ?  0   ?  ,   ?     ?  >        O     d     u  ?  ?     .  ?   0     ?  )     .   =  8   l     ?     ?     ?  9   ?  "   2  $   U  %   z     ?  *   ?  '   ?  ?        ?  #   ?               3     K     c  8   l     ?  6   ?     ?  )   ?  (   '     P  	   X  #   b  U   ?  ?   ?  *     @   G     ?  .   ?  	   ?  (   ?  $   ?  K      L   `   ,   ?   )   ?   <   !  4   A!     v!     ?!     ?!  ;   ?!     ?!  !   "     ="  +   Z"  0   ?"  N   ?"  %   #  4   ,#  4   a#     ?#  $   ?#     ?#  ;   ?#  $   2$  %   W$     }$      ?$     ?$      ?$     ?$      %  "   ,%     O%  *   [%  .   ?%  F   ?%     ?%  "   &     >&     B&  B   F&  B   ?&     ?&  "   ?&     '  
   '  
   '  )   ('  n   R'     ?'  )   ?'     	(     %(  5   =(  +   s(     ?(  ?   ?(     ?(     	)     )                <   C      =                F   W   0      .       6   b       U      '      !       \   O   7       5       `          9   ]          I   e   Z         J       
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
PO-Revision-Date: 2018-08-21 10:18+0000
Last-Translator: scootergrisen <scootergrisen@gmail.com>
Language-Team: Danish <dansk@dansk-gruppen.dk>
Language: da
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Plural-Forms: nplurals=2; plural=(n != 1);
X-Generator: Zanata 4.6.2
 
 
Bemærk: Dette output viser kun SysV-tjenester og inkluderer ikke native
      systemd-tjenester. SysV-konfigurationsdata vil muligvis blive overskrevet af den native
      systemd-konfiguration.

 
fejl ved læsning af valg
                     [--family <familje>]
                     [--initscript <tjeneste>]
                 --altdir <katalog> --admindir <katalog>
          %s --add <navn>
          %s --del <navn>
          %s --override <navn>
          %s [--level <niveau>] [--type <type>] <navn> %s
        alternatives --auto <navn>
        alternatives --config <navn>
        alternatives --display <navn>
        alternativer --list
        alternatives --remove <navn> <sti>
        alternatives --set <navn> <sti>
       Hvis du vil vise systemd-tjenster, så brug 'systemctl list-unit-files'.
      For at se tjenester som er aktiveret på et bestemt mål, brug
      'systemctl list-dependencies [mål]'.

   Valg         Kommando
  lænke peger i øjeblikket på %s
  slave %s: %s
 %s - status er auto.
 %s - status er manuel.
 %s eksisterer allerede
 %s tom!
 %s er ikke blevet konfigureret som et alternativ for %s
 %s version %s
 %s version %s - Ophavsret (C) 1997-2000 Red Hat, Inc.
 (ville fjerne %s
 --family må ikke indeholde symbolet '@'
 --type skal være "sysv" eller "xinetd"
 Tilbage Annullér Nuværende "bedste" version er %s.
 Tryk retur for at beholde det nuværende valg[+], eller indtast nummeret på valget:  Kunne ikke videresende tjenesteforespørgsel til systemctl: %m
 Ingen tjenester må håndteres af ntsysv!
 Bemærk: Forespørgsel om videresendelse til "systemctl %s %s".
 O.k. Tast <F1> for mere information om en tjeneste. Tjenester Der er %d programmmer som leverer "%s".
 Der er %d program som leverer "%s".
 Dette program må distribueres frit under vilkårene i GNU Public license.
 Dette program må distribueres frit under vilkårene i GNU Public license.

 Kan ikke sætte selinux-kontekst for %s: %s
 Hvilke tjenester skal startes automatisk? Du har ikke nok rettigheder til at udføre denne operation.
 Du skal være administrator (root) for at køre %s.
 adminkatalog %s ugyldig
 altkatalog %s ugyldig
 alternatives version %s
 alternatives version %s - Ophavsret (C) 2001 Red Hat, Inc.
 dårligt argument til --levels
 dårlig tilstand i linje 1 af %s
 dårlig primær lænke i %s
 kan ikke afgøre nuværende kørselsniveau
 lukkende '@' mangler eller familjen er tom i %s
 almindelige tilvalg: --verbose --test --help --usage --version --keep-missing
 fejl ved læsning fra katalog %s: %s
 fejl ved læsning af information om tjeneste %s: %s
 fejl ved læsning af information om tjeneste %s: %s
 kunne ikke oprette %s: %s
 kunne ikke 'globbe' mønster %s: %s
 kunne ikke lænke %s -> %s: %s
 kunne ikke linke %s -> %s: %s findes og er ikke et symlink
 kunne ikke oprette symlænke %s: %s
 lykkedes ikke at åbne %s/init.d: %s
 kunne ikke åbne %s: %s
 kunne ikke åbne katalog %s: %s
 kunne ikke læse %s: %s
 kunne ikke læse lænken %s: %s
 kunne ikke fjerne %s: %s
 kunne ikke fjerne lænke %s: %s
 kunne ikke erstatte %s med %s: %s
 familje %s  lænke %s er forkert for slave %s (%s %s)
 lænke ændret -- sætter tilstand til manuel
 lænke peger ikke på noget alternativ -- sætter tilstand til manuel
 mangler sti til slave %s i %s
 numerisk prioritet forventet i %s
 fra til kun én af --list, --add eller --del eller --override må angives
 kun ét kørselsniveau må angives for en chkconfig forespørgsel
 sti %s uventet i %s
 sti til alternativ forventet i %s
 prioritet %d
 læser %s
 kører %s
 tjeneste %s understøtter ikke chkconfig
 tjenesten %s understøtter chkconfig, men refereres ikke fra noget kørselsniveau (kør "chkconfig --add %s")
 sti til slave forventet i %s
 den primære lænke for %s skal være %s
 uventet filafslutning i %s
 uventet linje i %s: %s
 anvendelse:   %s <enable|disable|is-enabled> [navn] 
 brug:   %s [--list] [--type <type>] [navn]
 brug:   %s [navn]
 brug: alternatives --install <lænke> <navn> <sti> <prioritet>
 ville lænke %s -> %s
 ville fjerne %s
 xinetd baserede tjenester:
 