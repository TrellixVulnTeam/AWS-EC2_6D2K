??    g      T  ?   ?      ?     ?  ?   ?     h	  (   	  -   ?	  <   ?	     
     -
     G
  9   f
  "   ?
  $   ?
  %   ?
       +   *  (   V  ?        2     J     h     w     ?     ?  
   ?  4   ?     ?  6        >  &   P  "   w     ?     ?     ?  B   ?  3     &   <  /   c     ?  -   ?     ?  *   ?  (   ?  L   !  M   n  )   ?  .   ?  =        S     p     ?     ?  ;   ?     ?          !  #   9  1   ]  I   ?  $   ?  &   ?  ,   %     R     k     ?  ;   ?     ?                 7     X     o     ?     ?  !   ?  
   ?  '   ?  '     8   ?      x      ?     ?     ?  A   ?  9        =  !   W     y     ?     ?  &   ?  `   ?     &  #   A     e     ?  0   ?  ,   ?     ?  >        O     d     u  ?  ?     8  ?   :       (   .  ,   W  6   ?     ?     ?     ?  9     "   H  $   k  %   ?     ?  +   ?  (   ?  ?   '               4     C     a     {  	   ?  9   ?     ?  6   ?       /   1  *   a     ?  	   ?  $   ?  P   ?  6     3   K  =        ?  <   ?     ?  <      ;   B   L   ~   M   ?   8   !  3   R!  H   ?!  :   ?!     
"     !"     6"  ;   O"  "   ?"  $   ?"  !   ?"  /   ?"  5   %#  N   [#  %   ?#  8   ?#  <   	$      F$  /   g$  ,   ?$  J   ?$  ;   %  &   K%     r%  '   ?%     ?%  "   ?%  !   ?%  &   &  '   D&  
   l&  ,   w&  1   ?&  C   ?&     '  %   :'     `'     d'  S   h'  D   ?'     (  !   (     A(     P(  
   a(  '   l(  x   ?(     )  '   ()     P)     n)  5   ?)  -   ?)     ?)  A   *     F*     f*     {*                <   C      =                F   W   0      .       6   b       U      '      !       \   O   7       5       `          9   ]          I   e   Z         J       
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
PO-Revision-Date: 2017-06-14 03:05+0000
Last-Translator: Roman Spirgi <bigant@fedoraproject.org>
Language-Team: German <trans-de@lists.fedoraproject.org>
Language: de
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Plural-Forms: nplurals=2; plural=(n != 1);
X-Generator: Zanata 4.6.2
 
 
Hinweis: Diese Ausgabe zeigt lediglich SysV-Dienste und beinhaltet keine
         nativen systemd-Dienste. Die SysV-Konfigurationsdaten könnten durch
         die systemd-Konfiguration überschrieben werden.

 
Fehler beim Lesen der Auswahl
                     [--family <family>]
                     [--initscript <Dienst>]
                 --altdir <Ordner> --admindir <Ordner>
          %s --add <Name>
          %s --del <Name>
          %s --override <Name>
          %s [--level <levels>] [--type <type>] <Name> %s
        alternatives --auto <Name>
        alternatives --config <Name>
        alternatives --display <Name>
        alternatives --list
        alternatives --remove <Name> <Pfad>
        alternatives --set <Name> <Pfad>
       Verwenden Sie zum Auflisten von systemd-Diensten 'systemctl list-unit-files'.
      Verwenden Sie zum Auflisten von Diensten, die auf einem bestimmten Ziel aktiviert sind, 
      'systemctl list-dependencies [Ziel]'.

   Auswahl    Befehl
  Link verweist auf %s
  Slave %s: %s
 %s - Status ist automatisch.
 %s - Status ist manuell.
 %s bereits vorhanden
 %s leer!
 %s wurde nicht als eine Alternative für %s konfiguriert
 %s Version %s
 %s Version %s - Copyright (C) 1997-2008 Red Hat, Inc.
 (würde %s entfernen
 --family darf das »@«-Symbol nicht enthalten
 --type muss »sysv« oder »xinetd« sein
 Zurück Abbrechen Zur Zeit ist die `best' Version %s.
 Eingabe um die vorgegebene Auswahl[+] zu behalten, oder geben Sie die Nummer an: Fehler beim Weiterleiten der Anfrage an systemctl: %m
 Mit ntsysv können keine Dienste verwaltet werden!
 Hinweis: Anfrage wird weitergeleitet an »systemctl %s %s«.
 OK Weitere Informationen zu einem Dienst erhalten Sie mit <F1>. Dienste Es gibt %d Programme, welche »%s« zur Verfügung stellen.
 Es gibt %d Programm, welches »%s« zur Verfügung stellt.
 Kostenlose Weitergabe unter den Bedingungen der GNU Public License erlaubt.
 Kostenlose Weitergabe unter den Bedingungen der GNU Public License erlaubt.

 Selinux-Kontext konnte nicht für %s gesetzt werden: %s
 Welche Dienste sollen automatisch gestartet werden? Sie besitzen nicht die nötigen Rechte zum Ausführen dieser Operation.
 Sie müssen als root angemeldet sein, um %s auszuführen.
 admindir %s ungültig
 altdir %s ungültig
 alternatives Version %s
 alternatives Version %s - Copyright (C) 2001 Red Hat, Inc.
 Ungültiges Argument bei --levels
 Ungültiger Modus in Zeile 1 von %s
 Ungültiger primärer Link in %s
 aktueller Runlevel kann nicht ermittelt werden
 »@« fehlt am Ende oder die Familie ist leer bei %s
 Allgemeine Optionen: --verbose --test --help --usage --version --keep-missing
 Fehler beim Lesen des Ordners %s: %s
 Fehler beim Lesen von Informationen des Dienstes %s: %s
 Fehler beim Lesen der Informationen über den Dienst %s: %s
 Fehler beim Erzeugen von %s: %s
 Fehler beim Mustervergleich des Musters %s: %s
 Fehler beim Erstellen des Link %s -> %s: %s
 %s konnte nicht verbunden werden -> %s: %s existiert und ist kein Symlink
 Fehler beim Erstellen der symbolischen Verknüpfung %s: %s
 Fehler beim Öffnen von %s/init.d: %s
 Fehler beim Öffnen von %s: %s
 Fehler beim Öffnen des Ordners %s: %s
 Fehler beim Lesen von %s: %s
 Fehler beim Lesen von Link %s: %s
 Fehler beim Entfernen von %s: %s
 Fehler beim Entfernen des Link %s: %s
 Fehler beim Ersetzen von %s mit %s: %s
 Familie %s Link %s nicht richtig für Slave %s (%s %s)
 Link geändert -- Modus wird auf manuell gesetzt
 Link zeigt zu keiner Alternative -- Modus wird auf manuell gesetzt
 Pfad für Slave %s fehlt in %s
 Numerische Priorität in %s erwartet
 Aus Ein nur eines der Argumente --list, --add, --del oder --override darf angegeben werden
 für eine chkconfig-Anfrage kann nur ein Runlevel festgelegt werden
 Pfad %s nicht erwartet in %s
 Pfad zum Wechseln in %s erwartet
 Priorität %d
 %s wird gelesen
 läuft %s
 Dienst %s unterstützt chkconfig nicht
 Dienst %s unterstützt chkconfig, besitzt aber keinen Bezug auf einen Runlevel (führen Sie »chkconfig --add %s« aus)
 Slave-Pfad in %s erwartet
 Der primäre Link für %s muss %s sein
 Unerwartetes Dateiende in %s
 Unerwartete Zeile in %s: %s
 Verwendung:   %s <enable|disable|is-enabled> [name] 
 Aufruf:   %s [--list] [--type <type>] [name]
 Aufruf:   %s [Name]
 Aufruf: alternatives --install <Link> <Name> <Pfad> <Priorität>
 würde Link %s -> %s erstellen
 würde %s entfernen
 xinetd-basierende Dienste:
 