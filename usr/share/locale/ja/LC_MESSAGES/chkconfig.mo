??    g      T  ?   ?      ?     ?  ?   ?     h	  (   	  -   ?	  <   ?	     
     -
     G
  9   f
  "   ?
  $   ?
  %   ?
       +   *  (   V  ?        2     J     h     w     ?     ?  
   ?  4   ?     ?  6        >  &   P  "   w     ?     ?     ?  B   ?  3     &   <  /   c     ?  -   ?     ?  *   ?  (   ?  L   !  M   n  )   ?  .   ?  =        S     p     ?     ?  ;   ?     ?          !  #   9  1   ]  I   ?  $   ?  &   ?  ,   %     R     k     ?  ;   ?     ?                 7     X     o     ?     ?  !   ?  
   ?  '   ?  '     8   ?      x      ?     ?     ?  A   ?  9        =  !   W     y     ?     ?  &   ?  `   ?     &  #   A     e     ?  0   ?  ,   ?     ?  >        O     d     u  ?  ?     -    /  #   2  (   V  3     N   ?                :  C   [  $   ?  &   ?  '   ?       /   /  ,   _    ?     ?  /   ?     ?  &   ?  '   #     K     k  D   }     ?  >   ?       G   /  >   w     ?     ?  5   ?  Z       9   [   D   ?   4   ?      !  P   !     c!  7   p!  7   ?!  ~   ?!  m   _"  F   ?"  E   #  O   Z#  B   ?#     ?#     $      +$  C   L$  (   ?$  .   ?$  1   ?$  4   %  ?   O%  V   ?%  T   ?%  Z   ;&  Z   ?&      ?&  3   '  '   F'  ?   n'  H   (  9   c(  )   ?(  E   ?(  ,   )  *   :)  &   e)  $   ?)  0   ?)     ?)  <   ?)  1   3*  S   e*  ;   ?*  .   ?*     $+     (+  b   ++  V   ?+  /   ?+  .   ,     D,     R,     f,  E   t,  ?   ?,  1   =-  ,   o-  .   ?-  )   ?-  6   ?-  7   ,.     d.  L   ~.     ?.     ?.  !   ?.                <   C      =                F   W   0      .       6   b       U      '      !       \   O   7       5       `          9   ]          I   e   Z         J       
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
PO-Revision-Date: 2018-02-16 07:25+0000
Last-Translator: Casey Jones <nahareport@live.com>
Language-Team: Japanese <trans-ja@lists.fedoraproject.org>
Language: ja
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Plural-Forms: nplurals=1; plural=0;
X-Generator: Zanata 4.6.2
 
 
注記: この出力に含まれるのは SysV サービスのみです。ネイティブな 
      systemd サービスは含まれません。SysV の設定データはネイティブな
        systemd 設定で上書きされる場合があります。
 
選択の読み込みでエラー
                     [--family <family>]
                     [--initscript <サービス>]

                 --altdir <ディレクトリ> --admindir <ディレクトリ>
          %s --add <名前>
          %s --del <名前>
          %s --override <名前>
          %s [--level <レベル>] [--type <タイプ>] <名前> %s
        alternatives --auto <名前>
        alternatives --config <名前>
        alternatives --display <名前>
        alternatives --list
        alternatives --remove <名前> <パス>
        alternatives --set <名前> <パス>
       systemd サービスを一覧表示する場合は 'systemctl list-unit-files' を使用します。
      特定のターゲットで有効になっているサービスを確認する場合は
      'systemctl list-dependencies [target]'を使用します。

   選択       コマンド
 リンクは現在 %s を指しています。
  スレーブ %s: %s
 %s -ステータスは自動です。
 %s - ステータスは手動です。
 %s は既に存在します。
 %s は空です!
 %s は %s の為の互換用として設定されていません。
 %s バージョン %s
 %s バージョン %s - Copyright (C) 1997-2000 Red Hat, Inc.
 %s を削除する。
 --ファミリーには '@' 記号を含めることができません
 --type は 'sysv' か 'xinetd' でなければなりません
 戻る 取り消し 現在の「最適」バージョンは %s です。
 Enter を押して現在の選択 [+] を保持するか、選択番号を入力します: systemctl への要求の転送に失敗しました: %m
 ntsysv によって管理できるサービスがありません。
 情報:'systemctl %s %s'へ転送しています。
 OK サービスに関する詳細については、<F1> を押してください。 サービス %d プログラムがあり '%s' を提供します。
 %d プログラムがあり '%s' を提供します。
 このソフトウェアは GNU 一般公共使用許諾契約書に従って無償で再配布することができます。
 これは GNU 一般公有使用許諾書の規定の元で自由に再配布することができます。

 %s のためのSELinux コンテキストを設定できません: %s
 自動的に起動させるサービスを指定してください。 この操作を実行するためには権限が十分ではありません。
 %sを実行する為にルートでなければなりません。
 admindir %s は無効です。
 altdir %s は無効です。
 alternatives バージョン %s
 alternatives バージョン %s - Copyright (C) 2001 Red Hat, Inc.
 --levels の引数が不適当です。
 %s の 1 行目は不正なモードです。
 %s に不正な主要リンクがあります。
 現在のランレベルを識別できません。
 最後の '@' がないか、%s のファミリーが空です
 一般的なオプション: --verbose --test --help --usage --version --keep-missing
 ディレクトリ %s からの読み込み中にエラーが発生しました: %s
 サービス %s に関する情報の読み込み中にエラーが発生しました: %s
 サービス %s に関する情報の読み込み中にエラーが発生しました: %s
 %s の作成に失敗です: %s
 パターン %s の解析に失敗しました: %s
 %s から %s へのリンク失敗: %s
 シンボリックリンク %s -> %s の作成に失敗しました。 %s がすでに存在しており、シンボリックリンクファイルではありません。
 シンボリックリンク %s をつくるのに失敗しました: %s
 %s/init.d を開くことができませんでした: %s
 %s を開くのに失敗しました: %s
 ディレクトリ %s を開くことができませんでした: %s
 %s の読み込みに失敗しました: %s
 リンク %s の読み込みに失敗: %s
 %s の削除に失敗しました: %s
 リンク %s の削除に失敗: %s
 %s を %s への交換に失敗しました: %s
 ファミリー %s  リンク %s はスレーブ %s(%s %s)に不適切です。
 リンクの変更-- 手動に設定します。
 リンクはどの代替も指定していません -- 手動に設定します。
 %s にスレーブ %s のパスが欠如しています。
 %s に数値の優先が予想されます。
 off on 指定できるのは、 --list、 --add、 --del、 --override の中から 1 つだけです。
 chkconfig クエリに対して指定できるランレベルは 1 つだけです。
 %s に予想外のパス %s があります。
 %s に交替のパスが予想されます。
 優先度 %d
 %s 読み込み中
 %s 実行中
 サービス %s は、chkconfig をサポートしていません。
 サービス %s は chkconfig をサポートしますが実行レベルで参照されていません (run 'chkconfig --add %s')
 %s にスレーブパスを予想されます。
 %s の主要リンクは %s とします。
 %s が予想外なファイル終結です。
 %s に予想外の行があります: %s
 使用法:   %s <enable|disable|is-enabled> [名前] 
 使用法:   %s [--list] [--type <タイプ>] [名前]
 使用法:   %s [名前]
 使用法: alternatives --install <リンク> <名前> <パス> <優先度>
 %s から %s へリンク
 %s を削除する。
 xinetd ベースのサービス:
 