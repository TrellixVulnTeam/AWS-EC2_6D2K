??    g      T  ?   ?      ?     ?  ?   ?     h	  (   	  -   ?	  <   ?	     
     -
     G
  9   f
  "   ?
  $   ?
  %   ?
       +   *  (   V  ?        2     J     h     w     ?     ?  
   ?  4   ?     ?  6        >  &   P  "   w     ?     ?     ?  B   ?  3     &   <  /   c     ?  -   ?     ?  *   ?  (   ?  L   !  M   n  )   ?  .   ?  =        S     p     ?     ?  ;   ?     ?          !  #   9  1   ]  I   ?  $   ?  &   ?  ,   %     R     k     ?  ;   ?     ?                 7     X     o     ?     ?  !   ?  
   ?  '   ?  '     8   ?      x      ?     ?     ?  A   ?  9        =  !   W     y     ?     ?  &   ?  `   ?     &  #   A     e     ?  0   ?  ,   ?     ?  >        O     d     u  ?  ?     x  
  z  (   ?  (   ?  -   ?  <        B     \     v  9   ?  "   ?  $   ?  %        =  +   Y  (   ?    ?     ?  )   ?  ,         ;  &   \     ?     ?  J   ?     ?  0        B  K   _  W   ?  
            ,      [   H   B   ?   8   ?   H    !     i!  S   l!     ?!  U   ?!  S   #"  g   w"  h   ?"  P   H#  Y   ?#  q   ?#  E   e$  ,   ?$  (   ?$     %  7    %  2   X%  1   ?%  7   ?%  \   ?%  _   R&  X   ?&  7   '  J   C'  H   ?'  *   ?'  B   (  8   E(  ?   ~(  M   )  1   c)  *   ?)  9   ?)  .   ?)  ;   )*  *   e*  7   ?*  4   ?*     ?*  3   +  X   H+  ?   ?+  T   2,  A   ?,     ?,     ?,  l   ?,  Z   F-  )   ?-  >   ?-     
.     !.     2.  +   C.  ?   o.  d   /  A   ?/  3   ?/  .   ?/  G   '0  4   o0  *   ?0  E   ?0  0   1     F1  '   b1                <   C      =                F   W   0      .       6   b       U      '      !       \   O   7       5       `          9   ]          I   e   Z         J       
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
PO-Revision-Date: 2017-03-19 02:58+0000
Last-Translator: yuliya <ypoyarko@redhat.com>
Language-Team: Russian <trans-ru@lists.fedoraproject.org>
Language: ru
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Plural-Forms: nplurals=3; plural=(n%10==1 && n%100!=11 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2);
X-Generator: Zanata 4.6.2
 
 
Внимание! Ниже показаны только службы SysV (без служб systemd).
       Данные конфигурации SysV  могут быть переопределены
       нативной конфигурацией systemd.

 
ошибка чтения выбора
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
 Для просмотра полного списка служб systemd выполните: systemctl list-unit-files
Чтобы получить список служб для конкретной цели systemd выполните: 
systemctl list-dependencies [цель]

   Выбор    Команда
  ссылка указывает на %s
  подчиненная ссылка %s: %s
 %s - статус «авто».
 %s - статус «вручную».
 %s уже существует
 %s пуст!
 %s не был настроен как альтернатива для %s
 %s, версия %s
 %s версия %s. (C) 1997-2000 Red Hat, Inc.
 (будет удален %s
 --семейство не может содержать символ «@»
 В качестве значения --type надо выбрать sysv или xinetd
 Назад Отмена Оптимальная версия — %s.
 Enter - сохранить текущий выбор[+], или укажите номер:  Не удалось отправить запрос systemctl: %m
 Нет служб под управлением ntsysv!
 Запрос будет перенаправлен «systemctl %s %s».
 OK Нажмите <F1> для просмотра информации о службе. Службы Обнаружено %d программ(ы), предоставляющих «%s».
 Обнаружена %d программа, предоставляющая «%s».
 Может свободно распространяться на условиях GNU Public License.
 Может свободно распространяться на условиях GNU Public License.

 Не удалось установить контекст SELinux для %s: %s
 Какие сервисы должны запускаться автоматически? У вас недостаточно полномочий для выполнения этого действия.
 Для выполнения %s необходимы права root.
 неверный каталог admindir %s
 каталог altdir %s неверен
 alternatives, версия %s
 alternatives, версия %s,  (C) 2001 Red Hat, Inc.
 неверный аргумент для --levels
 неверный режим в строке 1 %s
 неверная первичная ссылка в %s
 не удается определить текущий уровень выполнения
 отсутствует замыкающий «@» или пустое семейство в %s
 общие параметры: --verbose --test --help --usage --version --keep-missing
 ошибка чтения из каталога %s: %s
 ошибка чтения информации для службы %s: %s
 ошибка чтения информации о сервисе %s: %s
 не удалось создать %s: %s
 невозможно использовать шаблон %s: %s
 ошибка создания ссылки %s -> %s: %s
 не удалось создать ссылку %s -> %s: %s уже существует и не является символьной ссылкой
 ошибка создания символической ссылки %s: %s
 не удалось открыть %s/init.d: %s
 не удается открыть %s: %s
 не удалось открыть каталог %s: %s
 не удается прочитать %s: %s
 не удается прочитать ссылку %s: %s
 не удается удалить %s: %s
 не удается удалить ссылку %s: %s
 не удается заменить %s на %s: %s
 семейство %s  неверная ссылка %s для %s (%s %s)
 ссылка изменена -- устанавливается ручной режим
 ссылка указывает на безальтернативный элемент - устанавливается ручной режим
 отсутствует путь для подчиненной ссылки %s в %s
 %s должен быть числовым приоритетом
 выкл вкл может быть указана лишь одна команда: --list, --add, --del или --override
 Необходимо указать лишь один уровень выполнения
 неожиданный путь %s в %s
 путь к альтернативе ожидается в %s
 приоритет %d
 чтение %s
 запуск %s
 %s не поддерживает chkconfig
 %s поддерживает chkconfig, но не используется ни на одном уровне выполнения (запустите «chkconfig --add %s»)
 в %s необходимо определить путь для подчиненной ссылки
 основной ссылкой на %s должна быть %s
 неожиданный конец файла в %s
 неожиданная строка в %s: %s
 Использование:   %s <enable|disable|is-enabled> [имя] 
 формат:  %s [--list] [--type <type>] [имя]
 Использование:   %s [имя]
 формат: alternatives --install <link> <name> <path> <priority>
 будет создана ссылка %s -> %s
 будет удален %s
 службы на основе xinetd:
 