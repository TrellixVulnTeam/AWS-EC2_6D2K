??    c      4  ?   L      p     q  ?   s     (	  -   ?	  <   m	     ?	     ?	     ?	  9   ?	  "   7
  $   Z
  %   
     ?
  +   ?
  (   ?
  ?        ?     ?     ?          $     <  
   O  4   Z     ?  6   ?     ?  "   ?     
            B   5  3   x  &   ?  /   ?       -        4  *   =  (   h  L   ?  M   ?  )   ,  .   V  =   ?     ?     ?     ?       ;   !     ]     w     ?  #   ?  I   ?  $     &   <  ,   c     ?     ?     ?  ;   ?     !     @     ^      u     ?     ?     ?     ?  !      '   "  '   J  8   r      ?      ?     ?     ?  A   ?  9   6     p  !   ?     ?     ?     ?  &   ?  `   ?     Y  #   t     ?     ?  0   ?  ,        /  >   C     ?     ?     ?  ?  ?     }  ?        P  .   h  >   ?     ?     ?     
  :   )  "   d  $   ?  %   ?     ?  .   ?  +     ?   I       '        C  !   T     v     ?  
   ?  5   ?     ?  6   ?     )  #   =     a     h      q  K   ?  D   ?  1   #  8   U     ?  9   ?  	   ?  $   ?  "   ?  K     L   i  2   ?  4   ?  G      -   f      ?      ?      ?   ;   ?   "   !      8!  $   Y!  ;   ~!  J   ?!      "  0   &"  1   W"     ?"  %   ?"     ?"  F   ?"  7   *#  '   b#     ?#  #   ?#     ?#      ?#  "   ?#  .   $  #   M$  1   q$  2   ?$  Q   ?$  (   (%  $   Q%     v%     {%  K   %  Q   ?%     &  '   :&     b&  	   q&     {&  '   ?&  }   ?&     0'  *   P'      {'     ?'  .   ?'  *   ?'     (  F   $(     k(     }(     ?(                9   @      :                C   S   .      ,       4   ^       Q      %   *          X   K   5       3       c          7   a          F       V      
   G       	              R   8       H   A   N   /   &      (   E   W      >       \       <   1      0   U      ]   _   B      -   #           '   =              [                   D   2                        ?   ;           J   O   )   6   I          !       T   b                       P          Z       `   $   +       M           Y      L   "    
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
 link %s incorrect for slave %s (%s %s)
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
PO-Revision-Date: 2017-04-15 10:58+0000
Last-Translator: Filipe Rosset <rosset.filipe@gmail.com>
Language-Team: Portuguese (Brazil) <trans-pt_br@lists.fedoraproject.org>
Language: pt_BR
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Plural-Forms: nplurals=2; plural=(n > 1);
X-Generator: Zanata 4.6.2
 
 
Nota: Esta saída mostra apenas os serviços SysV e não inclui
      os serviços nativos do systemd. Os dados de configuração do SysV podem ser sobrescritos pela
      configuração nativa do systemd.

 
erro ao ler a opção
                     [--initscript <serviço>]
                 --altdir <diretório> --admindir <diretório>
          %s --add <nome>
          %s --del <nome>
          %s --override <nome>
          %s [--level <níveis>] [--type <tipo>] <nome> %s
        alternatives --auto <nome>
        alternatives --config <nome>
        alternatives --display <nome>
        alternatives --list
        alternatives --remove <nome> <caminho>
        alternatives --set <nome> <caminho>
 Se você quiser listar os serviços do systemd, use 'systemctl list-unit-files'.
Para ver os serviços habilitados em um determinado alvo, use 
 'systemctl list-dependencies [target]'

   Seleção    Comando
  a ligação aponta atualmente para %s
  %s escravo: %s
 %s - o status está automático.
 %s - o status está manual.
 %s já existe
 %s vazio!
 %s não foi configurado como uma alternativa para %s
 %s versão %s
 %s versão %s - Copyright (C) 1997-2000 Red Hat, Inc.
 (%s será removido
 --type deve ser "sysv" ou "xinetd"
 Voltar Cancelar A "melhor" versão atual é %s.
 Indique para manter a seleção atual[+] ou digite o número da seleção:  Falha ao emcaminhar a requisição de serviço para o systemctl: %m
 Nenhum serviço pode ser gerenciado pelo ntsysv!
 Nota: Encaminhando requisição para 'systemctl %s %s'.
 Ok Pressione <F1> para mais informações sobre um serviço. Serviços Há %d programas que oferecem "%s".
 Há %d programa que oferece "%s".
 Pode ser redistribuído livremente sob os termos da Licença Pública GNU.
 Pode ser redistribuído livremente sob os termos da Licença Pública GNU.

 Impossível definir contexto SELinux para  %s: %s
 Quais serviços devem ser iniciados automaticamente? Você não tem privilégios suficientes para realizar esta operação.
 Você deve estar como root para executar %s.
 admindir %s inválido
 altdir %s inválido
 alternatives versão %s
 alternatives versão %s - Copyright (C) 2001 Red Hat, Inc.
 argumento inválido para --levels
 modo inválido na linha 1 do %s
 ligação primária inválida em %s
 não foi possível determinar o nível de execução atual
 opções comuns: --verbose --test --help --usage --version --keep-missing
 erro ao ler o diretório %s: %s
 erro ao ler informação para o serviço %s: %s
 erro ao ler informação sobre o serviço %s: %s
 falha ao criar %s: %s
 impossível definir o padrão %s: %s
 falha ao ligar %s -> %s: %s
 falha no link %s -> %s: %s, ele existe mas não é um link simbólico
 não foi possível criar a ligação simbólica %s: %s
 não foi possível abrir %s/init.d: %s
 falha ao abrir %s: %s
 falha ao abrir o diretório %s: %s
 falha ao ler %s: %s
 falha ao ler a ligação %s: %s
 não foi possível remover %s: %s
 não foi possível remover a ligação %s: %s
 falha ao  substituir %s por %s: %s
 ligação %s incorreta para o escravo %s (%s %s)
 a ligação mudou - configurando para modo manual
 A ligação não aponta para nenhuma alternativa - configurando para modo manual
 falta o caminho para o escravo %s em %s
 prioridade numérica esperada em %s
 não sim apenas uma destas pode ser especificada --list, --add, --del ou --override
 somente um nível de execução pode ser indicado para uma consulta do chkconfig
 caminho %s inesperado em %s
 caminho a ser alternado esperado em %s
 prioridade %d
 lendo %s
 executando %s
 o serviço %s não suporta o chkconfig
 o serviço %s suporta o chkconfig, mas não está referenciado em nenhum nível de execução (execute "chkconfig --add %s")
 caminho escravo esperado em %s
 a ligação primária para %s deve ser %s
 fim inesperado do arquivo em %s
 linha inesperada em %s: %s
 uso:   %s <enable|disable|is-enabled> [name] 
 uso:   %s [--list] [--type <tipo>] [nome]
 uso:   %s [nome]
 uso: alternatives --install <ligação> <nome> <caminho> <prioridade>
 ligará %s -> %s
 %s será removido
 servidos baseados no xinetd:
 