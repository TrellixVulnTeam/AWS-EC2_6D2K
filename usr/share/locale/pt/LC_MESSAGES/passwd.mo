??    9      ?  O   ?      ?     ?  @     1   E  )   w  '   ?  3   ?  (   ?  &   &     M  4   j     ?  !   ?  8   ?  !     $   5  "   Z     }  4   ?  "   ?  '   ?          :     R     b     h     ?     ?     ?  4   ?     	      	     1	     J	     c	     	     ?	  $   ?	     ?	     ?	     
      
  "   6
  *   Y
     ?
  X   ?
  5   ?
     -  &   =  3   d  %   ?  %   ?  U   ?  L   :  &   ?  7   ?  5   ?  ?    &   ?  N   
  9   Y  /   ?  8   ?  <   ?  7   9  3   q  /   ?  E   ?          ;  I   [  '   ?  8   ?  0     (   7  B   `  /   ?  6   ?  &   
     1     Q     b     g  "   ?  %   ?     ?  3   ?  $        >     O     j     ?     ?     ?  /   ?  $        6     >  (   X  -   ?  2   ?     ?  Y   ?  -   Y     ?  0   ?  .   ?  2   ?  2   /  \   b  N   ?  1     E   @  1   ?             '   +   8          &   5               *       (                 .   3      $   1         #                        %         /                        2             7       ,   -   )                    	       "       9           
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
PO-Revision-Date: 2016-09-05 10:43-0400
Last-Translator: Ricardo Pinto <ricardo.bigote@gmail.com>
Language-Team: Portuguese <trans-pt@lists.fedoraproject.org>
Language: pt
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Plural-Forms: nplurals=2; plural=(n != 1);
X-Generator: Zanata 3.9.6
 %s: Não é possível identificá-lo!
 %s: Não poderá misturar uma das opções -l, -u, -d, -S com -i, -n, -w, -x.
 %s: Só poderá indicar uma das opções -l, -u, -d, -S.
 %s: Só poderá indicar um nome de utilizador.
 %s: Só o 'root' poderá indicar um nome de utilizador.
 %s: SELinux a negar acesso devido a politica de segurança.
 %s: O nome de utilizador indicado é demasiado grande.
 %s: Esta opção precisa de um nome de utilizador.
 %s: O nome de utilizador '%s' é desconhecido.
 %s: todos os itens de autenticação foram actualizados com sucesso.
 %s: argumento inválido %s: %s
 %s: erro ao ler do 'stdin': %s
 %s: os itens de autenticação expirados foram actualizados com sucesso.
 %s: erro de inicialização da libuser: %s: não é possível definir o atraso entre falhas: %s
 %s: não é possível atribuir o TTY ao PAM: %s
 %s: não é possível iniciar o PAM: %s
 %s: a conta do utilizador não tem suporte para prazos de senhas.
 A ajustar os dados de prazos do utilizador %s.
 Esquema de autenticação alternativo em utilização. A modificar a senha do utilizador %s.
 componente da senha corrompido. Senha em branco. Erro Erro (senha não definida?) A expirar senha do utilizador %s.
 A bloquear a senha do utilizador %s.
 Nenhuma senha definida.
 Nota: apagar uma senha também desbloqueia a senha. Só poderá fazer isto como 'root'.
 Senha bloqueada. Senha definida, cifra DES. Senha definida, cifra MD5. Senha definida, cifra SHA256. Senha definida, cifra SHA512. Senha definida, cifra blowfish. Senha definida, variante de cifra desconhecida. A remover a senha do utilizador %s.
 Sucesso Utilizador desconhecido.
 A desbloquear a senha do utilizador %s.
 Operação insegura (use o '-f' para obrigar) Atenção: a senha desbloqueada ficaria em branco. [OPÇÃO...] <nome da conta> apague a senha para a conta nomeada (apenas root); também remove algum bloqueio da senha Expirar a senha para esta conta (apenas root) forçar a operação manter os itens de autenticação não-expirados Bloquear a senha para esta conta (apenas root) tempo de vida máximo da senha (apenas com 'root') tempo de vida mínimo da senha (apenas com 'root') nº de dias após a expiração da senha até à desactivação da conta (apenas com 'root') nº de dias de aviso aos utilizadores antes da expiração (apenas com 'root') ler os itens novos do 'stdin' (apenas com 'root') devolver o estado do utilizador da conta indicada (apenas com 'root') Desbloquear a senha para esta conta (apenas root) 