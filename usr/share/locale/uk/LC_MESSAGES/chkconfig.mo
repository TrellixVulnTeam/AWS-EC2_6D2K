??    g      T  ?   ?      ?     ?  ?   ?     h	  (   	  -   ?	  <   ?	     
     -
     G
  9   f
  "   ?
  $   ?
  %   ?
       +   *  (   V  ?        2     J     h     w     ?     ?  
   ?  4   ?     ?  6        >  &   P  "   w     ?     ?     ?  B   ?  3     &   <  /   c     ?  -   ?     ?  *   ?  (   ?  L   !  M   n  )   ?  .   ?  =        S     p     ?     ?  ;   ?     ?          !  #   9  1   ]  I   ?  $   ?  &   ?  ,   %     R     k     ?  ;   ?     ?                 7     X     o     ?     ?  !   ?  
   ?  '   ?  '     8   ?      x      ?     ?     ?  A   ?  9        =  !   W     y     ?     ?  &   ?  `   ?     &  #   A     e     ?  0   ?  ,   ?     ?  >        O     d     u    ?     ?  1  ?  ,   ?  4     2   ;  F   n  !   ?  !   ?  &   ?  F      (   g  *   ?  +   ?     ?  5     2   9  U  l     ?  6   ?          (     C     b     x  P   ?     ?  ;   ?     /   ;   O   G   ?   
   ?      ?   5   ?   [   '!  u   ?!  9   ?!  \   3"     ?"  _   ?"     ?"  <   
#  <   G#  p   ?#  p   ?#  P   f$  I   ?$  c   %  n   e%  4   ?%  2   	&     <&  8   Z&  6   ?&  7   ?&  <   '  Z   ?'  n   ?'  ^   	(  9   h(  D   ?(  J   ?(  .   2)  =   a)  G   ?)  ?   ?)  V   v*  5   ?*  .   +  =   2+  0   p+  C   ?+  .   ?+  A   ,  6   V,     ?,  ?   ?,  Z   ?,  ?   ?-  0   ?-  C   ?-     C.  
   L.  k   W.  n   ?.  +   2/  B   ^/      ?/     ?/     ?/  2   ?/  ?   %0  /   ?0  A   1  7   O1  .   ?1  I   ?1  I    2  ,   J2  s   w2  6   ?2     "3  3   @3                <   C      =                F   W   0      .       6   b       U      '      !       \   O   7       5       `          9   ]          I   e   Z         J       
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
PO-Revision-Date: 2020-01-30 16:16+0000
Last-Translator: Yuri Chornoivan <yurchor@ukr.net>
Language-Team: Ukrainian <https://translate.fedoraproject.org/projects/fedora-sysv/chkconfig/uk/>
Language: uk
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Plural-Forms: nplurals=3; plural=n%10==1 && n%100!=11 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2;
X-Generator: Weblate 3.10.3
 
 
Зауваження: у виведених даних показано лише служби SysV, там немає типових
      служб systemd. Дані налаштування SysV могли бути перезаписані типовими
      налаштуваннями systemd.
 
помилка читання вибору
                     [--family <сімейство>]
                     [--initscript <служба>]
                 --altdir <каталог> --admindir <каталог>
          %s --add <служба>
          %s --del <служба>
          %s --override <служба>
          %s [--level <рівні>] [--type <тип] <служба> %s
        alternatives --auto <назва>
        alternatives --config <назва>
        alternatives --display <назва>
        alternatives --list
        alternatives --remove <назва> <шлях>
        alternatives --set <назва> <шлях>
       Якщо вам потрібен список служб systemd, скористайтеся командою «systemctl list-unit-files».
      Щоб переглянути служби, увімкнені для певної мети, скористайтеся командою
      «systemctl list-dependencies [мета]».

   Вибір    Команда
  посилання наразі вказує на %s
  slave %s: %s
 %s - стан "авто".
 %s - стан "вручну".
 %s вже існує
 %s порожній!
 %s не було налаштовано як альтернативу для %s
 %s версія %s
 %s версія %s - Copyright (C) 1997-2000 Red Hat, Inc.
 ( буде видалено %s
 --family не може містити символу «@»
 аргументом --type має бути «sysv» або «xinetd»
 Назад Скасувати Поточна "найкраща" версія - %s.
 Enter - зберегти поточний вибір[+], або вкажіть номер:  Не вдалося переспрямувати запит щодо обслуговування до systemctl: %m
 Немає служб, які керуються ntsysv!
 Зауваження: переспрямування запиту до «systemctl %s %s».
 Гаразд Натисніть <F1> для докладнішої інформації про службу. Служби Є %d програм, які забезпечують '%s'.
 Є %d програм, які забезпечують '%s'.
 Може вільно розповсюджуватись на умовах ліцензії GNU Public License.
 Може вільно розповсюджуватись за умов дотримання GNU Public License.
 Не вдалося встановити контекст selinux для %s: %s
 Які служби треба запускати автоматично? У вас недостатньо повноважень для виконання цієї дії.
 Для виконання %s необхідні повноваження адміністратора (root).
 каталог admindir %s неправильний
 каталог altdir %s неправильний
 alternatives версія %s
 alternatives версія %s — © Red Hat, Inc., 2001
 неправильний аргумент в --levels
 неправильний режим у рядку 1 %s
 неправильне основне посилання %s
 не вдається визначити поточний рівень виконання
 пропущено завершальний символ «@» або порожнє сімейство у %s
 загальні параметри: --verbose --test --help --usage --version --keep-missing
 помилка читання з каталогу %s: %s
 помилка читання даних для служби %s: %s
 помилка читання інформації у службі %s: %s
 не вдається створити %s: %s
 не вдається визначити шаблон %s: %s
 не вдається створити посилання %s -> %s: %s
 не вдалося створити посилання %s -> %s: %s вже існує і не є символічним посиланням
 не вдається створити символічне посилання %s: %s
 не вдається відкрити %s/init.d: %s
 не вдається відкрити %s: %s
 не вдається відкрити каталог %s: %s
 не вдається прочитати %s: %s
 не вдається прочитати посилання %s: %s
 не вдається видалити %s: %s
 не вдається видалити посилання %s: %s
 не вдається замінити %s на %s: %s
 сімейство %s  посилання %s неправильне для %s (%s %s)
 посилання змінено -- встановлюється ручний режим
 посилання вказує на безальтернативний елемент - встановлюється ручний режим
 відсутній шлях до slave %s у %s
 %s повинен бути числовим пріоритетом
 вимк ввімк можна вказувати лише один аргумент з --list, --add, --del або --override
 можна вказувати лише один рівень виконання для запиту chkconfig
 неочікуваний шлях %s у %s
 у %s очікується шлях до альтернативи
 пріоритетність %d
 читаємо %s
 запускається %s
 служба %s не підтримує chkconfig
 служба %s підтримує chkconfig, але не використовується на жодному рівні виконання (запустіть 'chkconfig --add %s')
 у %s очікувався шлях до slave
 основним посиланням на %s має бути %s
 неочікуваний кінець файла у %s
 неочікуваний рядок у %s: %s
 Користування:   %s <enable|disable|is-enabled> [назва] 
 використання:   %s [--list] [--type <тип>] [служба]
 користування:   %s [назва]
 використання: alternatives --install <посилання> <назва> <шлях> <пріоритет>
 буде створено посилання %s -> %s
 буде видалено %s
 служби, що базуються на xinetd:
 