??    g      T  ?   ?      ?     ?  ?   ?     h	  (   	  -   ?	  <   ?	     
     -
     G
  9   f
  "   ?
  $   ?
  %   ?
       +   *  (   V  ?        2     J     h     w     ?     ?  
   ?  4   ?     ?  6        >  &   P  "   w     ?     ?     ?  B   ?  3     &   <  /   c     ?  -   ?     ?  *   ?  (   ?  L   !  M   n  )   ?  .   ?  =        S     p     ?     ?  ;   ?     ?          !  #   9  1   ]  I   ?  $   ?  &   ?  ,   %     R     k     ?  ;   ?     ?                 7     X     o     ?     ?  !   ?  
   ?  '   ?  '     8   ?      x      ?     ?     ?  A   ?  9        =  !   W     y     ?     ?  &   ?  `   ?     &  #   A     e     ?  0   ?  ,   ?     ?  >        O     d     u  ?  ?     H  ?   J     ?  (     -   +  <   Y     ?     ?     ?  9   ?  "   #  $   F  %   k     ?  +   ?  (   ?  ?        ?     ?               .     J     [  )   i     ?  ;   ?     ?      ?  0        >     E  "   L  ?   o  +   ?  '   ?  7        ;  0   B     s  "   z  "   ?  X   ?  [      (   u   !   ?   .   ?   %   ?      !     )!     ;!  @   S!      ?!     ?!     ?!  "   ?!  4   "  H   D"     ?"  %   ?"  (   ?"     ?"     #  %   ,#  @   R#  "   ?#     ?#     ?#     ?#     $     $     8$     N$     k$  
   ?$  .   ?$  )   ?$  ;   ?$  %   )%     O%     o%     v%  E   }%  3   ?%  !   ?%  !   &     ;&     I&     Z&     h&  e   ?&     ?&     	'     )'  !   I'  2   k'  ,   ?'     ?'  @   ?'     "(     6(     D(                <   C      =                F   W   0      .       6   b       U      '      !       \   O   7       5       `          9   ]          I   e   Z         J       
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
PO-Revision-Date: 2017-09-05 06:11+0000
Last-Translator: Copied by Zanata <copied-by-zanata@zanata.org>
Language-Team: Chinese (Taiwan) <trans-zh_TW@lists.fedoraproject.org>
Language: zh_TW
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Plural-Forms: nplurals=1; plural=0;
X-Generator: Zanata 4.6.2
 
 
注意：本輸出僅顯示 SysV 服務，並且不包含原生的 systemd 服務。
      SysV 組態資料可能會被原生的 systemd 組態凌駕。

 
讀取選擇發生錯誤
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
       若您希望列出 systemd 服務，請使用「systemctl list-unit-files」。
      若要查看啟用於特定目的地上的服務，請使用
      「systemctl list-dependencies [target]」。

   選擇        指令
  目前連結指向 %s
  從屬 %s：%s
 %s - 狀態是自動的。
 %s - 狀態是手動的。
 %s 已經存在
 %s 空白！
 %s 尚未被設定為 %s 的替代選項
 %s 版本 %s
 %s 版本 %s - 著作權所有 (C) 1997-2000 Red Hat, Inc.
 (會移除 %s
 --family 無法取得符號 '@'
 --type 必須要是「sysv」或是「xinetd」
 返回 取消 目前「最佳」版本為 %s。
 請輸入以保留目前的選擇[+]，或輸入選擇號碼： 無法轉送服務請求至 systemctl：%m
 無任何服務可被 ntsysv 管理！
 注意：正在轉送請求至「systemctl %s %s」。
 確定 請按 <F1> 查看該項服務的更多資訊。 服務 有 %d 個程式提供「%s」。
 有 %d 個程式提供「%s」。
 在遵守 GNU 通用公共授權 (GPL) 的條款下，可以自由散布這個程式。
 在遵守 GNU 通用公共授權 (GPL) 的條款下，可以自由的散佈這個程式。
 無法為 %s 設定 selinux 情境：%s
 那些服務應被自動啟動？ 您沒有足夠的權力進行這項操作。
 您必須是 root 才能執行 %s。
 admindir %s 無效
 altdir %s 無效
 alternatives 版本 %s
 alternatives 版本 %s - 著作權所有 (C) 2001 Red Hat, Inc.
 在 --levels 處有不良引數
 %s 的第一列模式不良
 %s 的主要連結不良
 無法取得目前的執行層級
 關閉用的 '@' 遺失，或家族在 %s 中空白
 常用選項：--verbose --test --help --usage --version --keep-missing
 讀取 %s 目錄錯誤：%s
 讀取 %s 服務的資訊錯誤：%s
 在 %s 服務上讀取訊息錯誤：%s
 建立 %s 失敗：%s
 設定 glob 樣式 %s：%s
 建立 %s -> %s 的連結失敗：%s
 無法連結 %s -> %s：%s 已存在，而且不是符號連結
 建立 %s 符號連結失敗：%s
 無法開啟 %s/init.d：%s
 無法開啟 %s：%s
 無法開啟 %s 目錄：%s
 無法讀取 %s：%s
 無法讀取連結 %s：%s
 無法移除 %s：%s
 移除 %s 連結失敗：%s
 取代 %s 以 %s 失敗：%s
 家族 %s  %s 連結在從屬 %s 上是錯誤的 (%s %s)
 連結已改變 -- 設定為手動模式
 連結未指向任何替代選項 -- 設定為手動模式
 遺失 %2$s 中的從屬 %1$s 路徑
 %s 中預期有優先度數字
 關閉 開啟 只能指定 --list, --add, --del, 或 --override 中的其中一個
 只能對 chkconfig 查詢指定一種執行層級
 %2$s 中沒有預期 %1$s 路徑
 %s 中有預期 alternate 路徑
 優先度 %d
 正在讀取 %s
 執行中 %s
 %s 服務不支援 chkconfig
 %s 服務支援 chkconfig，但未向任何執行層級註冊（請執行「chkconfig --add %s」）
 %s 中預期有從屬路徑
 %s 的主要連結必須是 %s
 %s 中沒有預期檔案結尾
 %s 中有未預期的一列：%s
 用法：  %s <enable|disable|is-enabled> [name] 
 用法：%s [--list] [--type <type>] [name]
 用法：  %s [name]
 用法：alternatives --install <link> <name> <path> <priority>
 會連結 %s -> %s
 會移除 %s
 以 xinetd 為主的服務：
 