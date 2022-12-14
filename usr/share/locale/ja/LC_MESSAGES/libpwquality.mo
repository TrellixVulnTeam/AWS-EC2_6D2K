??    6      ?  I   |      ?  L   ?     ?     ?       0   .  *   _  
   ?     ?     ?  $   ?     ?     ?  %     B   .  #   q     ?  !   ?      ?     ?          /  #   N  2   r  5   ?  *   ?  5     ?   <  5   |  C   ?  N   ?  A   E	  0   ?	  $   ?	  /   ?	  9   
  /   G
  @   w
  I   ?
  <     G   ?  +   ?  6   ?  '   ?       $   /  +   T  '   ?     ?  *   ?     ?     ?          %  ?  7  b   ?     K  $   k  -   ?  S   ?  ?        R  *   a  !   ?  E   ?     ?  0     '   E  \   m  A   ?  C     .   P  1     *   ?  -   ?  '   
  9   2  ]   l  V   ?  M   !  h   o  M   ?  h   &  _   ?  h   ?  _   X  `   ?  <     W   V  <   ?  W   ?  T   C  W   ?  N   ?  r   ?  K   ?  K   ?  B   J  '   ?  K   ?  >     H   @  *   ?  H   ?     ?       2         S     #                             !          $              1   +                 '                4   /   .   &       )   3                 %   
             ,   *   5                0       -   	         "             2   6                      (                        The command reads the password to be scored from the standard input.
 BAD PASSWORD: %s Bad integer value Bad integer value of setting Cannot obtain random numbers from the RNG device Could not obtain the password to be scored Error: %s
 Fatal failure Memory allocation error Memory allocation error when setting New %s%spassword:  No password supplied Opening the configuration file failed Password generation failed - required entropy too low for settings Password quality check failed:
 %s
 Retype new %s%spassword:  Setting %s is not of integer type Setting %s is not of string type Setting is not of integer type Setting is not of string type Sorry, passwords do not match. The configuration file is malformed The password contains forbidden words in some form The password contains less than %ld character classes The password contains less than %ld digits The password contains less than %ld lowercase letters The password contains less than %ld non-alphanumeric characters The password contains less than %ld uppercase letters The password contains monotonic sequence longer than %ld characters The password contains more than %ld characters of the same class consecutively The password contains more than %ld same characters consecutively The password contains the user name in some form The password contains too few digits The password contains too few lowercase letters The password contains too few non-alphanumeric characters The password contains too few uppercase letters The password contains too long of a monotonic character sequence The password contains too many characters of the same class consecutively The password contains too many same characters consecutively The password contains words from the real name of the user in some form The password differs with case changes only The password does not contain enough character classes The password fails the dictionary check The password is a palindrome The password is just rotated old one The password is shorter than %ld characters The password is the same as the old one The password is too short The password is too similar to the old one Unknown error Unknown setting Usage: %s <entropy-bits>
 Usage: %s [user]
 Project-Id-Version: libpwquality 1.2.4
Report-Msgid-Bugs-To: http://fedorahosted.org/libpwquality
POT-Creation-Date: 2017-05-26 16:44+0200
PO-Revision-Date: 2016-03-31 03:51-0400
Last-Translator: Noriko Mizumoto <noriko@redhat.com>
Language-Team: LANGUAGE <LL@li.org>
Language: ja
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Plural-Forms: nplurals=1; plural=0
X-Generator: Zanata 3.9.6
        このコマンドは採点するパスワードを標準入力から読み込みます。
 よくないパスワード: %s 良くない整数型の値です。 設定の良くない整数型の値です。 RNG(乱数発生)デバイスから乱数を取得することができません。 採点するパスワードを取得できませんでした。 エラー: %s
 致命的な障害が発生しました。 メモリー割り当てエラー 設定中にメモリー割り当てエラーが発生しました。 新しい %s%s パスワード: パスワードが与えられていません。 設定ファイルを開けません。 パスワードの生成に失敗 -設定に必要なエンピロピーが小すぎます。 パスワードの品質チェックに失敗しました。
 %s
 新しい %s%s パスワードをもう一度力してください: 設定 %s は整数型ではありません。 設定 %s は文字列型ではありません。 設定は整数型ではありません。 設定は文字列型ではありません。 パスワードが一致しません。 設定ファイルの形式が正しくありません。 このパスワードには何らかの形で禁止された単語が含まれています。 このパスワードは %ld 種類未満の文字の種類が含まれています。 このパスワードには %ld 個未満の数字が含まれています。 このパスワードには %ld 個未満の小文字のアルファベットが含まれています。 このパスワードには %ld 個未満の記号が含まれています。 このパスワードには %ld 個未満の大文字のアルファベットが含まれています。 このパスワードには %ld 文字より長い単調な文字列が含まれています。 このパスワードは %ld 個を越える連続する同じ種類の文字が含まれています。 このパスワードは %ld 個を越える連続する同じ文字が含まれています。 このパスワードには一部に何らかの形でユーザー名が含まれています。 このパスワードは数字の個数が足りません。 このパスワードは小文字のアルファベットの個数が足りません。 このパスワードは記号の個数が足りません。 このパスワードは大文字のアルファベットの個数が足りません。 このパスワードには長すぎる単調な文字列が含まれています。 このパスワードには連続して同じ種類の文字が含まれています。 このパスワードには連続して同じ文字が含まれています。 このパスワードには何らかの形でユーザーの本名から基づく単語が含まれています。 このパスワードは大文字と小文字を変更しただけです。 このパスワードに含まれる文字の種類数が足りません。 このパスワードは辞書チェックに失敗しました。 このパスワードは回文です。 このパスワードは単に古いものを回転させただけです。 このパスワードは %ld 文字未満の文字列です。 このパスワードは過去に設定されたものと同じです。 このパスワードは短すぎます。 このパスワードは古いパスワードと似すぎています。 不明なエラー 未知の設定 使い方: %s <エントロピーのビット数>
 使い方: %s [user]
 