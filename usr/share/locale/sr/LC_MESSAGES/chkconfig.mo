??    `        ?         (     )  ?   +     ?  -   ?  <   %	     b	     |	     ?	  9   ?	  "   ?	  $   
  %   7
     ]
  +   y
  (   ?
  ?   ?
     ?     ?     ?     ?     ?     ?  
     4        G  6   V     ?  "   ?     ?     ?     ?  B   ?  3   0  &   d  /   ?     ?  -   ?     ?  *   ?  (      L   I  M   ?  )   ?  .     =   =     {     ?     ?     ?  ;   ?          /     I  #   a  $   ?  &   ?  ,   ?     ?          6  ;   S     ?     ?     ?      ?               7     P  !   n  '   ?  '   ?  8   ?            :     [     _  A   b  9   ?     ?  !   ?          &  &   2  `   Y     ?  #   ?     ?       ,   2     _  >   s     ?     ?     ?  ?  ?     ?  ,  ?  /     4   D  X   y     ?     ?  !     F   .  '   u  )   ?  *   ?  '   ?  8     5   S  $  ?  #   ?  2   ?       -   !  #   O     s     ?  C   ?     ?  K   ?     E  8   `  
   ?     ?  >   ?  h   ?  c   Y  J   ?  P         Y   K   e      ?   E   ?   ?   !  ?   F!  ?   ?!  M   _"  Q   ?"  f   ?"  :   f#  !   ?#     ?#     ?#  P   $  &   T$  $   {$  '   ?$  Q   ?$  H   %  K   c%  K   ?%  +   ?%  <   '&  5   d&  n   ?&  I   	'  2   S'  +   ?'  F   ?'  '   ?'  0   !(  +   R(  4   ~(  /   ?(  >   ?(  H   ")  e   k)  C   ?)  =   *     S*     f*  \   w*  i   ?*  -   >+  B   l+     ?+     ?+  0   ?+  ?   ,  ;   ?,  5   ?,  5   #-  &   Y-  =   ?-     ?-  a   ?-     ?.     _.  2   y.            /           _      0   $      !   %          E   U             M       Q   '   `       #          W               6   -      5   K   =      1   P   (   7      ,                          B   
   T   S   H   )       I   G            >       ;       D   ]      +                  :       V      F   Z   &       .       ^      C           8   X      @   Y   <   2       "      A   3   \           L          	   O       [   N   J   4   R   9           ?                                *    
 
Note: This output shows SysV services only and does not include native
      systemd services. SysV configuration data might be overridden by native
      systemd configuration.

 
error reading choice
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
 link %s incorrect for slave %s (%s %s)
 link changed -- setting mode to manual
 link points to no alternative -- setting mode to manual
 missing path for slave %s in %s
 numeric priority expected in %s
 off on only one of --list, --add, --del, or --override may be specified
 only one runlevel may be specified for a chkconfig query
 path %s unexpected in %s
 path to alternate expected in %s
 reading %s
 running %s
 service %s does not support chkconfig
 service %s supports chkconfig, but is not referenced in any runlevel (run 'chkconfig --add %s')
 slave path expected in %s
 the primary link for %s must be %s
 unexpected end of file in %s
 unexpected line in %s: %s
 usage:   %s [--list] [--type <type>] [name]
 usage:   %s [name]
 usage: alternatives --install <link> <name> <path> <priority>
 would link %s -> %s
 would remove %s
 xinetd based services:
 Project-Id-Version: PACKAGE VERSION
Report-Msgid-Bugs-To: 
POT-Creation-Date: 2017-07-25 13:31+0200
PO-Revision-Date: 2015-04-29 03:09+0000
Last-Translator: Momcilo Medic <medicmomcilo@gmail.com>
Language-Team: Serbian <trans-sr@lists.fedoraproject.org>
Language: sr
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Plural-Forms: nplurals=3; plural=(n%10==1 && n%100!=11 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2);
X-Generator: Zanata 4.6.2
 
 
Напомена: Овај приказ показује само SysV сервисе и не укључује природне
      systemd сервисе. SysV подаци за подешавања могу бити преписани природним
      systemd подешавањима.

 
грешка при читању избора
                       [--initscript <сервис>]
               --altdir <директоријум> --admindir <директоријум>
           %s --add <име>
           %s --del <име>
           %s --override <име>
           %s [--level <нивои>] [--type <врста>] <име> %s
           alternatives --auto <име>
           alternatives --config <име>
           alternatives --display <име>
        алтернативно --list
           alternatives --remove <име> <путања>
           alternatives --set <име> <путања>
       Ако желите да излистате systemd сервисе користите 'systemctl list-unit-files'.
      Да видите који су сервису омогућени на одређеном циљу користите
      'systemctl list-dependencies [target]'.

    Избор       Наредба
  веза тренутно указује на %s
  подређени %s: %s
 %s - статус је самосталан.
 %s - статус је ручни.
 %s већ постоји
 празан %s!
 %s није подешено као алтернатива за %s
 %s верзија %s
 %s верзија %s - Ауторска права 1997-2000 Red Hat, Inc.
 (уклонило би %s
 --type мора бити „sysv“ или „xinetd“
 Назад Откажи Тренутна „најбоља“ верзија је %s.
 <Enter> задржава тренутни избор[+], или укуцајте број избора:  Неуспешно преусмеравање сервисног захтева на systemctl: %m
 Ниједним сервисом не сме да управља ntsysv!
 Напомена: Преусмеравам захтев на 'systemctl %s %s'.
 У реду Притисните <F1> за више података о сервису. Сервиси Постоји %d програма који пружају „%s“.
 Постоји %d програм који пружа „%s“.
 Ово се сме слободно раздељивати у складу са одредбама ГНУ Опште јавне лиценце.
 Ово се сме слободно делити у складу са одредбама ГНУ Опште јавне лиценце.

 Немогуће постављање selinux контекста за %s: %s
 Који сервиси треба самостално да се покрећу? Немате довољне повластице за извршавање ове операције.
 Морате бити root да би извршили %s.
 admindir %s неисправан
 altdir %s неисправан
 alternatives верзија %s
 alternatives верзија %s - Ауторска права 2001 Red Hat, Inc.
 лош аргумент за --levels
 лош режим у 1. реду %s
 лоша основна веза у %s
 не могу да одредим тренутни ниво извршавања
 грешка при читању из директоријума %s: %s
 грешка при читању података о сервису %s: %s
 грешка при читању података о сервису %s: %s
 неуспешно стварање %s: %s
 неуспешно поклапање обрасца %s: %s
 неуспешно повезивање %s -> %s: %s
 неуспешно повезивање %s -> %s: %s постоји и није симболичка веза
 неуспешно прављење симболичке везе %s: %s
 неуспешно отварање %s/init.d: %s
 неуспешно отварање %s: %s
 неуспешно отварање директоријума %s: %s
 неуспешно читање %s: %s
 неуспешно читање везе %s: %s
 неуспешно уклањање %s: %s
 неуспешно уклањање везе %s: %s
 неуспешна замена %s са %s: %s
 %s веза нетачна за подређени %s (%s %s)
 промењена веза -- постављам ручни режим
 веза не указује на алтернативу -- постављам ручни режим
 недостаје путања за подређеног %s у %s
 бројчано првенство очекивано у %s
 искључено укључено можете навести само један од --list, --add, --del или --override
 само један ниво извршавања сме бити наведен у chkconfig упиту
 %s путања неочекивана у %s
 путања до алтернативе очекивана у %s
 читам %s
 извршавам %s
 сервис %s не подржава chkconfig
 сервис %s подржава chkconfig, али није познат ни у једном нивоу извршавања (извршите „chkconfig --add %s“)
 путања подређеног очекивана у %s
 основна веза за %s мора бити %s
 неочекиван крај датотеке у %s
 неочекиван ред у %s: %s
 употреба: %s [--list] [--type <врста>] [име]
 употреба:   %s [name]
 употреба: alternatives --install <веза> <име> <путања> <првенство>
 повезало би %s -> %s
 би уклонило %s
 сервиси засновани на xinetd-у:
 