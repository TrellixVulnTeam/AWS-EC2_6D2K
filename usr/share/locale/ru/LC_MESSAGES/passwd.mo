??    9      ?  O   ?      ?     ?  @     1   E  )   w  '   ?  3   ?  (   ?  &   &     M  4   j     ?  !   ?  8   ?  !     $   5  "   Z     }  4   ?  "   ?  '   ?          :     R     b     h     ?     ?     ?  4   ?     	      	     1	     J	     c	     	     ?	  $   ?	     ?	     ?	     
      
  "   6
  *   Y
     ?
  X   ?
  5   ?
     -  &   =  3   d  %   ?  %   ?  U   ?  L   :  &   ?  7   ?  5   ?      ;     ?   Z  U   ?  F   1  T   x  l   ?  C   :  _   ~  *   ?  Q   	  -   [  -   ?  `   ?  4     K   M  9   ?  6   ?  c   
  ?   n  i   ?  =   ^  0   ?     ?     ?  ,   ?  _   "  H   ?     ?  i   ?  \   S  &   ?  %   ?  %   ?  (   #  (   L  *   u  6   ?  D   ?       1   +  @   ]  ?   ?  m     2   ?  O   ?  N     1   _  X   ?  T   ?  S   ?  Q   ?  ?   ?  ?   ?  K   L  d   ?  V   ?             '   +   8          &   5               *       (                 .   3      $   1         #                        %         /                        2             7       ,   -   )                    	       "       9           
          !         4                 0   6    %s: Can not identify you!
 %s: Cannot mix one of -l, -u, -d, -S and one of -i, -n, -w, -x.
 %s: Only one of -l, -u, -d, -S may be specified.
 %s: Only one user name may be specified.
 %s: Only root can specify a user name.
 %s: SELinux denying access due to security policy.
 %s: The user name supplied is too long.
 %s: This option requires a user name.
 %s: Unknown user name '%s'.
 %s: all authentication tokens updated successfully.
 %s: bad argument %s: %s
 %s: error reading from stdin: %s
 %s: expired authentication tokens updated successfully.
 %s: libuser initialization error: %s: unable to set failure delay: %s
 %s: unable to set tty for pam: %s
 %s: unable to start pam: %s
 %s: user account has no support for password aging.
 Adjusting aging data for user %s.
 Alternate authentication scheme in use. Changing password for user %s.
 Corrupted passwd entry. Empty password. Error Error (password not set?) Expiring password for user %s.
 Locking password for user %s.
 No password set.
 Note: deleting a password also unlocks the password. Only root can do that.
 Password locked. Password set, DES crypt. Password set, MD5 crypt. Password set, SHA256 crypt. Password set, SHA512 crypt. Password set, blowfish crypt. Password set, unknown crypt variant. Removing password for user %s.
 Success Unknown user.
 Unlocking password for user %s.
 Unsafe operation (use -f to force) Warning: unlocked password would be empty. [OPTION...] <accountName> delete the password for the named account (root only); also removes password lock if any expire the password for the named account (root only) force operation keep non-expired authentication tokens lock the password for the named account (root only) maximum password lifetime (root only) minimum password lifetime (root only) number of days after password expiration when an account becomes disabled (root only) number of days warning users receives before password expiration (root only) read new tokens from stdin (root only) report password status on the named account (root only) unlock the password for the named account (root only) Project-Id-Version: passwd 0.79
Report-Msgid-Bugs-To: http://bugzilla.redhat.com/
POT-Creation-Date: 2018-04-01 02:30+0200
PO-Revision-Date: 2016-03-29 08:21-0400
Last-Translator: yuliya <ypoyarko@redhat.com>
Language-Team: Russian <trans-ru@lists.fedoraproject.org>
Language: ru
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Plural-Forms: nplurals=3; plural=(n%10==1 && n%100!=11 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2);
X-Generator: Zanata 3.9.6
 %s: не могу вас идентифицировать!
 %s: ключи -l, -u, -d, -S не могут использоваться совместно с ключами -i, -n, -w, -x.
 %s: ожидается только один параметр: -l, -u, -d или -S.
 %s: необходимо указать только одно имя.
 %s: только root может выбрать имя учетной записи.
 %s: отказано в  доступе согласно политике безопасности SELinux.
 %s: имя пользователя слишком длинное.
 %s: для этого параметра необходимо имя пользователя.
 %s: неизвестное имя «%s».
 %s: данные аутентификации успешно обновлены.
 %s: неверный аргумент %s: %s
 %s: ошибка чтения из stdin: %s
 %s: устаревшие данные аутентификации были обновлены.
 %s: ошибка инициализации libuser: %s: невозможно задать задержку при сбое: %s
 %s: невозможно задать tty для pam: %s
 %s: небезопасно запускать pam: %s
 %s: учетная запись не поддерживает устаревание пароля.
 Устанавливаются параметры истечения срока действия для пользователя %s.
 Используется альтернативная схема проверки подлинности. Изменение пароля пользователя %s.
 Поврежденная запись в passwd. Пустой пароль. Ошибка Ошибка (пароль не задан?) Срок действия пароля пользователя %s заканчивается.
 Блокируется пароль для пользователя %s.
 Пароль не задан
 Примечание. Удаление пароля вызовет его разблокирование. Для выполнения этой операции необходимы права root.
 Пароль заблокирован. Пароль задан, шифр DES Пароль задан, шифр MD5 Пароль задан, шифр SHA256 Пароль задан, шифр SHA512 Пароль задан, шифр blowfish Пароль задан, шифр неизвестен Удаляется пароль для пользователя %s.
 Успешно Неизвестный пользователь.
 Снимается блокировка пароля для %s.
 Небезопасная операция (используйте -f для принудительного выполнения) Предупреждение. После разблокирования пароль будет пустым. [ПАРАМЕТРЫ...] <пользователь> удалить пароль, сняв блокировку (только root)  просрочить пароль пользователя (только root) принудительное выполнение хранить действующие данные авторизации (пароли) заблокировать пароль пользователя (только root) максимальный срок действия пароля (только root) минимальный срок действия пароля (только root) период ожидания после окончания действия пароля, по истечении которого учетная запись будет заблокирована (только root) период предупреждений (в днях) до окончания срока действия пароля (только root) получить новое значение из stdin (только root) сообщить состояние пароля для пользователя (только root) разблокировать пароль пользователя (только root) 