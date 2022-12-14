??    6      ?  I   |      ?  L   ?     ?     ?       0   .  *   _  
   ?     ?     ?  $   ?     ?     ?  %     B   .  #   q     ?  !   ?      ?     ?          /  #   N  2   r  5   ?  *   ?  5     ?   <  5   |  C   ?  N   ?  A   E	  0   ?	  $   ?	  /   ?	  9   
  /   G
  @   w
  I   ?
  <     G   ?  +   ?  6   ?  '   ?       $   /  +   T  '   ?     ?  *   ?     ?     ?          %  ?  7  ;   ?     3     H     [  &   w     ?     ?     ?     ?  $   ?          $     4  0   J     {      ?     ?     ?     ?          2     K  *   a  )   ?  #   ?  )   ?  8     )   =  /   g  5   ?  /   ?  *   ?     (  !   D  0   f  !   ?  !   ?  -   ?  '   	  0   1  !   b  $   ?  $   ?     ?  !   ?          !     7     D     `     m     z     ?     #                             !          $              1   +                 '                4   /   .   &       )   3                 %   
             ,   *   5                0       -   	         "             2   6                      (                        The command reads the password to be scored from the standard input.
 BAD PASSWORD: %s Bad integer value Bad integer value of setting Cannot obtain random numbers from the RNG device Could not obtain the password to be scored Error: %s
 Fatal failure Memory allocation error Memory allocation error when setting New %s%spassword:  No password supplied Opening the configuration file failed Password generation failed - required entropy too low for settings Password quality check failed:
 %s
 Retype new %s%spassword:  Setting %s is not of integer type Setting %s is not of string type Setting is not of integer type Setting is not of string type Sorry, passwords do not match. The configuration file is malformed The password contains forbidden words in some form The password contains less than %ld character classes The password contains less than %ld digits The password contains less than %ld lowercase letters The password contains less than %ld non-alphanumeric characters The password contains less than %ld uppercase letters The password contains monotonic sequence longer than %ld characters The password contains more than %ld characters of the same class consecutively The password contains more than %ld same characters consecutively The password contains the user name in some form The password contains too few digits The password contains too few lowercase letters The password contains too few non-alphanumeric characters The password contains too few uppercase letters The password contains too long of a monotonic character sequence The password contains too many characters of the same class consecutively The password contains too many same characters consecutively The password contains words from the real name of the user in some form The password differs with case changes only The password does not contain enough character classes The password fails the dictionary check The password is a palindrome The password is just rotated old one The password is shorter than %ld characters The password is the same as the old one The password is too short The password is too similar to the old one Unknown error Unknown setting Usage: %s <entropy-bits>
 Usage: %s [user]
 Project-Id-Version: libpwquality 1.2.4
Report-Msgid-Bugs-To: http://fedorahosted.org/libpwquality
POT-Creation-Date: 2017-05-26 16:44+0200
PO-Revision-Date: 2015-03-14 08:40-0400
Last-Translator: Copied by Zanata <copied-by-zanata@zanata.org>
Language-Team: LANGUAGE <LL@li.org>
Language: zh_TW
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Plural-Forms: nplurals=1; plural=0;
X-Generator: Zanata 3.9.6
        本指令會從標準輸入讀取密碼來評分。
 不良的密碼：%s 不良的整數值 設定的值為不良整數 無法從 RNG 裝置取得隨機號碼 無法取得要評分的密碼 錯誤：%s
 重大失敗 記憶體分配錯誤 設定時發生記憶體分配錯誤 新 %s%s密碼： 未提供密碼 組態檔開啟失敗 密碼產生失敗 - 設定所需要的熵太低 密碼品質檢查失敗：
%s
 再次輸入新的 %s%s密碼： %s 設定的類型不是整數 %s 設定的類型不是字串 設定的類型不是整數 設定的類型不是字串 抱歉，密碼不符。 組態檔格式不良 密碼以某種形式包含禁止的單詞 密碼包含的字元型別少於 %ld 種 密碼包含的數字少於 %ld 個 密碼包含的小寫字母少於 %ld 個 密碼包含的非字母與非數字字元少於 %ld 個 密碼包含的大寫字母少於 %ld 個 密碼包含長於 %ld 個字元的單調序段 密碼包含的連續相同型別字元超過 %ld 個 密碼包含的連續相同字元超過 %ld 個 密碼以某種形式包含使用者名稱 密碼包含的數字太少 密碼包含的小寫字母太少 密碼包含的非字母與非數字字元過少 密碼包含的大寫字母太少 密碼包含過長的單調順序 密碼包含太多連續的相同型別字元 密碼包含太多連續的相同字元 密碼以某種形式包含使用者真名的字 密碼只有大小寫改變而已 密碼不包含足夠的字元型別 密碼無法通過字典比對檢查 密碼為迴文形式 密碼就只是以前某個舊的 密碼短於 %ld 個字元 密碼與舊的相同 密碼過短 密碼與舊的太過相像 未知錯誤 未知設定 用法：%s <entropy-bits>
 用法：%s [user]
 