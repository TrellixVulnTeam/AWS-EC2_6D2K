??    ?      ?  ?   	         ?  !  C  ?  K   ?  &   F     m  ?   ?     #     6     K     b  +   y     ?     ?  #   ?  +   ?  :   (     c  '   ~     ?  &   ?     ?  :   ?  %   4  6   Z     ?     ?  1   ?     ?  !     $   *  2   O  /   ?  &   ?  _   ?  0   9      j  $   ?  .   ?  -   ?          -  9   L     ?     ?  "   ?     ?     ?     ?  )   ?     '     <     R     f  $   ?     ?     ?     ?     ?          0  4   G     |     ?  %   ?     ?  .   ?  -     -   C     q     ?     ?  /   ?  !   ?            -     N  !   m  #   ?  (   ?     ?     ?  /     I   J  -   ?     ?  -   ?          %  ,   <  F   i  C   ?     ?       8        Q     i  B   ?  !   ?     ?  $     5   )  /   _  /   ?  &   ?     ?  &     $   (  '   M     u  5   ?  >   ?               5   ;      q   2   ?      ?      ?      ?      ?      ?   #   !     &!     A!  ,   \!     ?!  "   ?!  ,   ?!  J   ?!     9"     Y"  (   h"  ,   ?"  /   ?"  ^   ?"  )   M#  )   w#  E   ?#  ^   ?#  4   F$  '   {$     ?$     ?$  ?  ?$  ?  6&    ?'  <   ?)  !   0*     R*  ?   j*     +     +     ,+     B+  5   _+     ?+     ?+  &   ?+  '   ?+     ,     0,  !   O,     q,  )   ?,     ?,  0   ?,     ?,  4   -     F-  
   \-  9   g-  '   ?-  !   ?-  &   ?-  =   .  4   P.  '   ?.  ^   ?.  *   /     7/  !   V/  3   x/  ,   ?/     ?/     ?/  6   0     N0     ]0     v0     ?0     ?0     ?0  )   ?0     ?0      1     1     ,1  )   B1  )   l1     ?1     ?1     ?1     ?1     2  2   '2     Z2     l2  .   ?2     ?2  #   ?2  #   ?2  #   3     +3     D3     ]3  <   y3     ?3     ?3     ?3  *   4     ,4  $   K4     p4     ?4     ?4  0   ?4  H   ?4  '   D5     l5      ?5     ?5     ?5  0   ?5  U   6  U   b6     ?6     ?6  <   ?6     7     ,7  6   H7  "   7     ?7  *   ?7  *   ?7  0   8  $   B8  '   g8     ?8  !   ?8     ?8     ?8     9  ,   9  6   K9     ?9     ?9  $   ?9     ?9  :   ?9     ):     =:     ?:     U:     ^:     y:     ?:     ?:  0   ?:     ?:     ;  -   .;  C   \;     ?;     ?;  $   ?;  *   ?;  +   %<  \   Q<  (   ?<  '   ?<  F   ?<  Y   F=  =   ?=     ?=     ?=  	    >           o      c       N   ?   I   *   .           y   %       n       B          X   ?       |                 
       5       H   ?   2      x   6       1                  R   3       U   l   Q   s      ;   @   ?   0   ?          ?   K       /      J       <                     +             f   e   z   j   -       4          #   i       L          (   	   Z   ?       T       ~   `              S   ?              w   ?      ?   ?       9   ]      v   7   ?       m   M   W   F   d   _   Y          ?       D   "   O   !      p       ^       E   8   b   ?   C           }       g   {   ,   ?       u   )   k   A   ?   =              q          >   [      G       a   \   r       ?   &      '   :   ?      V          P   t   $       h    
  enable name/project [chroot]
  disable name/project
  remove name/project
  list --installed/enabled/disabled
  list --available-by-user=NAME
  search project

  Examples:
  copr enable rhscl/perl516 epel-6-x86_64
  copr enable ignatenkobrain/ocltoys
  copr disable rhscl/perl516
  copr remove rhscl/perl516
  copr list --enabled
  copr list --available-by-user=ignatenkobrain
  copr search tests
     
You are about to enable a Copr repository. Please note that this
repository is not part of the main distribution, and quality may vary.

The Fedora Project does not exercise any power over the contents of
this repository beyond the rules outlined in the Copr FAQ at
<https://docs.pagure.org/copr.copr/user_documentation.html#what-i-can-build-in-copr>,
and packages are not held to any quality or security level.

Please do not file bug reports about these packages in Fedora
Bugzilla. In case of problems, contact the owner of this repository.

Do you really want to enable {0}? 
You are about to enable a Playground repository.

Do you want to continue? '%s' is not of the format 'MACRO EXPR' '{}' is not a directory * These coprs have repo file with an old format that contains no information about Copr hub - the default one was assumed. Re-enable the project to fix this. Adding exclude on: Adding repo from: %s Adding versionlock on: Bad dnf debug file: %s Can't parse repositories for username '{}'. Can't parse search for '{}'. Can't write file '{}' Check closure for this package only Check only the newest packages in the repos Configuration of repo failed Configuration of repos failed Copying '{}' to local repo Could not make repository directory: %s Could not open {} Could not save repo to repofile %s: %s Deleting versionlock for: Display a list of unresolved dependencies for repositories Download package to current directory Download target '{}' is outside of download path '{}'. Error in resolve of packages: Error:  Excludes from versionlock plugin were not applied Exiting due to strict setting. Failed to disable copr repo {}/{} Failed to get mirror for package: %s Failed to open: '%s', not a valid source rpm file. Failed to open: '%s', not a valid spec file: %s Failed to remove copr repo {0}/{1}/{2} Ignore architecture and install missing packages matching the name, epoch, version and release. Install the latest version of recorded packages. Interact with Copr repositories. Interact with Playground repository. List all installed Copr repositories (default) List available Copr repositories by user NAME List disabled Copr repositories List enabled Copr repositories List installed packages not required by any other package List of {} coprs Locklist not set Manage a directory of rpm packages Matched: {} Migrating history data... New leaves: Newest N packages to keep - defaults to 1 No description given No description given. No files to process No match for argument: %s No matching package to install: '%s' No matching repo to modify: %s. No package %s available. No package found for: No source rpm defined for %s Not all dependencies satisfied Nothing provides: '%s' Output a full package dependency graph in dot format Output written to: %s Package %s is not available Pass either --old or --new, not both! Path to directory Playground repositories successfully disabled. Playground repositories successfully enabled. Playground repositories successfully updated. Print the newest packages Print the older packages Rebuilding local repo Repoclosure ended with unresolved dependencies. Repository successfully disabled. Repository successfully enabled. Repository successfully removed. Safe and good answer. Exiting. Some packages could not be found. Space separated output, not newline Specify an instance of Copr to work with Specify repositories to check Such repository does not exist. This command has to be run under the root user. This repository does not have any builds yet so you cannot enable it now. Unable to create a directory '{}' due to '{}' Unable to find a match Unable to read version lock configuration: %s Unknown response from server. Unknown subcommand {}. Versionlock plugin: could not parse pattern: Versionlock plugin: number of exclude rules from file "{}" applied: {} Versionlock plugin: number of lock rules from file "{}" applied: {} [DELETED] %s [PACKAGE|PACKAGE.spec] add (and enable) the repo from the specified file or url also download comps.xml bad copr project format check packages of the given archs, can be specified multiple times comps.xml for repository %s saved control package version locks define a macro for spec file parsing delete local packages no longer present in repository determine updated binaries that need restarting do not attempt to dump the repository contents. download all packages from remote repo download all the metadata. download only newest packages per-repo download only packages for this ARCH download the -debuginfo package instead download the src.rpm instead dump information about installed rpm packages to file exactly two additional parameters to copr command are required failed to delete file %s install debuginfo packages limit  the  query to packages of given architectures. limit to specified type migrate yum's history, group and yumdb data to dnf multiple hubs specified n name of dump file no no package matched: %s only consider this user's processes operate on source packages optional name of dump file output commands that would be run to stdout. packages to download packages with builddeps to install print current configuration values to stdout print list of urls where the rpms can be downloaded instead of downloading print variable values to stdout repo to modify resolve and download needed dependencies restore packages recorded in debug-dump file save the current options (useful with --setopt) specify Copr hub either with `--hub` or using `copr_hub/copr_username/copr_projectname` format treat commandline arguments as source rpm treat commandline arguments as spec files use format `copr_username/copr_projectname` to reference copr project when running with --resolve, download all dependencies (do not exclude already installed ones) when running with --url, limit to specific protocols where to store downloaded repositories  y yes Project-Id-Version: PACKAGE VERSION
Report-Msgid-Bugs-To: 
POT-Creation-Date: 2020-03-19 14:54+0100
PO-Revision-Date: 2019-04-02 05:18+0000
Last-Translator: Cheng-Chia Tseng <pswo10680@gmail.com>
Language-Team: Chinese (Taiwan)
Language: zh_TW
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Plural-Forms: nplurals=1; plural=0;
X-Generator: Zanata 4.6.2
 
  enable 名稱 / 專案 [chroot]
  disable 名稱 / 專案 
  remove 名稱 / 專案 
  list --installed/enabled/disabled
  list --available-by-user=NAME
  search 專案

  範例：
  copr enable rhscl/perl516 epel-6-x86_64
  copr enable ignatenkobrain/ocltoys
  copr disable rhscl/perl516
  copr remove rhscl/perl516
  copr list --enabled
  copr list --available-by-user=ignatenkobrain
  copr search tests
     
您正打算啟用一個 Copr 軟體庫。請注意這個軟體庫
不是主散布版的一部分，並且品質不定。

Fedora Project 不會對這個軟體庫的內容行使任何超出 Copr 常見問題（<https://docs.pagure.org/copr.copr/user_documentation.html#what-i-can-build-in-copr>）列出規則之外的權力，且軟體包並不保有任何的品質與安全性保證。

請不要發送關於這些軟體包的漏洞回報至 Fedora Bugzilla。假如碰到問題，請聯絡此軟體庫的擁有者。

仍要啟用 {0}？ 
您正打算啟用 Playground 軟體庫。

確定繼續？ 「%s」非格式「MACRO EXPR」 '{}' 不是個資料夾 * 這些 Copr 包含舊格式的 repo 檔案，其可能不包含 Copr hub 的資訊 - 已假定為預設值。重新啟用專案以修復此問題。 增加排除於： 增加軟體庫自：%s 增加版本鎖於： 壞的 dnf 偵錯檔案：%s 無法解析為使用者名稱「{}」的軟體庫。 無法解析搜尋「{}」。 無法寫入檔案 '{}' 檢查只有這個軟體庫的 closure 只檢查軟體庫內最新的軟體包 設定軟體庫失敗 複製 '{}' 至本機軟體庫 無法創建存儲庫目錄： %s 無法打開 {} 無法儲存軟體庫至 repofile %s：%s 移除版本鎖為： 顯示軟體庫中未回應的依賴關係列表 下載軟體包至目前目錄 下載目標「{}」在下載位置「{}」之外。 解析包時出錯： 錯誤：  從版本鎖附加元件排除的項目將不會被套用 因為建構體設定，所以退出。 無法停用 Copr 軟體庫 {}/{} 無法取得此軟體庫的鏡像：%s 無法開啟：「%s」，不是有效的來源 rpm 檔案。 無法開啟：「%s」，非有效 spec 檔案：%s 無法移除 copr 軟體庫 {0}/{1}/{2} 忽略 CPU 架構，並安裝符合名字、epoch、版本與釋出版本的遺失軟體包。 安裝已紀錄軟體包的最新版本。 與 Copr 軟體庫相互作用 與 Playground 軟體庫互動。 列出所有安裝的 Copr 軟體庫（預設值） 由 user NAME 列出可用的 Copr 軟體庫 列出停用的 Copr 軟體庫 列出啟用的 Copr 軟體庫 由其他軟體包列出不需要的已安裝軟體包 列出 {} Copr 鎖定列表尚未設定 管理 rpm 軟體包目錄 符合：{} 遷移歷史資料中… 新保留： 保留 N 個新軟體包 - 預設值為 1 沒有提供描述 沒有提供描述。 沒有檔案要操作 參數不匹配： %s 沒有符合的項目以安裝：「%s」 沒有符合的軟體庫以變更：%s。 沒有軟體包 %s 可用。 沒有軟體包被找到於： %s 沒有來源 RPM 指定 並非所有的依賴都滿足 沒有提供者：「%s」 以 dot 格式輸出完整的軟體包依賴關係 輸出寫至：%s 軟體包 %s 不可用 通過 --old 或 --new，不能兩個一起！ 目錄路徑 Playground 軟體庫成功停用。 Playground 軟體庫成功啟用。 Playground 軟體庫成功更新。 顯示較新的軟體包 顯示較舊的軟體包 重新架構本機軟體庫 因為未回應的依賴關係列表，Repoclosure 退出。 軟體庫順利停用。 軟體庫順利啟用。 軟體庫順利移除。 安全、且更棒的回應。退出中。 有些軟體包遍尋不著。 空白分割輸出而非換行符號 指定 Copr 的作業實例： 指定欲檢查的軟體庫 這樣的軟體庫不存在。 這個指令需要以 root 使用者權限執行 這個軟體庫尚未擁有任何 build，所以您還不能啟用它。 無法建立目錄 '{}'，原因：'{}' 無法找到匹配項 無法讀取版本鎖設定：%s 來自伺服器的未知回應 未知的子指令 {}。 Versionlock 外掛程式：無法解析範本： Versionlock 外掛程式：來自「{}」檔案的排除條件數量已經套用：{} Versionlock 外掛程式：來自「{}」檔案的封鎖條件數量已經套用：{} [DELETED] %s [PACKAGE|PACKAGE.spec] 從指定的檔案或網址增加（和啟用）此軟體庫 還下載comps.xml 損壞的 Copr 專案格式 檢查給予的架構的軟體包，可指定多個。 comps.xml for repository %s 保存 控制軟體包版本鎖 定義一個巨集作為 spec 檔案解析 刪除存儲庫中不再存在的本地包 判定需要重新啟動的更新後二進位檔 不要嘗試傾印軟體庫資訊。 從遠端軟體庫下載所有軟體包 下載所有的中繼資料。 每次只下載最新的軟件包 僅下載此ARCH的軟件包 改下載 -debuginfo 軟體包 改下載 src.rpm 傾印安裝的 RPM 軟體包資訊至檔案 究竟 Copr 指令上兩個選用的參數是否需要 無法刪除文件 %s 安裝 debuginfo 軟體包 限制查詢給予架構的軟體包 限制指定的類型 遷移 yum 的歷史紀錄、群組與 yumdb 資料至 dnf 指定了多個 hub n 傾印檔案的名稱 否 (no) 沒有軟體包符合：%s 只考慮該使用者的程序 在源包上運行 傾印檔案的選用名字 輸出指令，使其能執行至標準輸出。 要下載的軟體包 builddeps 要安裝的軟體包 顯示目前的設定檔的值至標準輸出 顯示出 URL 列表，使 RPM 可以直接使用而不須下載。 顯示變數值至標準輸出 要修改的軟體庫 解析並下載需要的依賴軟體 在偵錯傾印檔案還原軟體包記錄 儲存目前的設定（ 用於 --setopt） 對 Copr hub 指定任選 `--hub` 或使用 `copr_hub/copr_username/copr_projectname` 格式 處理指令列上的參數為來源 rpm 處理指令列的參數為 spec 檔案 使用 format `copr_username / copr_projectname` 來參考 Copr 專案 當透過 --resolve 執行時，下載所有相依軟體包 (不排除已下載的項目) 當使用 --url 參數執行，限制指定的通訊協定。 儲存下載軟體庫的地方  y 是 (yes) 