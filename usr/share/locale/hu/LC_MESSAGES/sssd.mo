??    G      T  a   ?        '        9  3   N  %   ?      ?     ?     ?  #   ?          <  ,   W     ?  +   ?  $   ?  "   ?  ,     	   8     B  
   R     ]     l  )   s     ?     ?  8   ?      	  
   	     	  '   2	     Z	     i	  )   ?	  $   ?	     ?	     ?	     ?	     ?	  /   
     =
     L
     [
  +   t
  (   ?
  
   ?
     ?
     ?
  $        '     B     Y     r     ?  !   ?     ?     ?  /   ?          *  2   >     q     ?     ?  .   ?  '   ?  *        /  D   B  (   ?  $   ?     ?  ?  ?  .   ?  (     2   +  .   ^     ?     ?     ?  7   ?  9     *   X  <   ?     ?  :   ?  6     (   E  :   n     ?     ?     ?     ?  	   ?  /   ?  5        U  B   g     ?     ?     ?  E   ?     +     ?  ?   [  +   ?     ?     ?  %   ?  $     -   7     e     r  *   ?  )   ?  9   ?  	        !     :     P  #   p  #   ?     ?     ?     ?  )   ?  %   "  )   H  G   r     ?     ?  1   ?           )     J  7   f  F   ?  ?   ?     %  Z   6  4   ?      ?     ?     ?   =                          .       A   7   @      ;   '   2   $   D   8   E   0       C   
   5      4                 (             9   -                                     )   &          6      *   /                         G           1   	          !   #                <   3   ,   %       F   "      +                     B   >               :    , your cached password will expire at:  Add debug timestamps An error occurred, but no description can be found. Authenticated with cached credentials Authentication is denied until:  Authentication provider Authentication timeout Cache credentials for offline login Cannot get info about the user
 Cannot set default values
 Create user's directory if it does not exist Current Password:  Do not remove home directory and mail spool Entry cache timeout length (seconds) File that contains CA certificates Force removal of files not owned by the user Full Name GECOS attribute Group name Group password Groups Groups that SSSD should explicitly ignore Groups to add this user to Home directory How many failed logins attempts are allowed when offline IPA client hostname IPA domain IPA server address Internal error. Could not remove user.
 Kerberos realm Kerberos server address Kill users' processes before removing him Length of time to attempt connection Lock the account Login shell Maximum user ID Minimum user ID Never create user's directory, overrides config New Password:  Out of memory
 Password change failed.  Password expired. Change your password now. Password reset by root is not supported. Password:  Passwords do not match Reenter new Password:  Require TLS certificate verification Require TLS for ID lookups SSSD Services to start SSSD is not run by root. Server message:  Shell attribute Show timestamps with microseconds Specify user to delete
 Specify user to modify
 System is offline, password change not possible The GID of the group The GID of the user The Schema Type in use on the LDAP server, rfc2307 The UID of the user The default base DN The default bind DN The selected UID is outside the allowed range
 Transaction error. Could not add user.
 Transaction error. Could not modify user.
 Unlock the account User's home directory already exists, not copying data from skeldir
 Users that SSSD should explicitly ignore ldap_uri, The URI of the LDAP server memberOf attribute Project-Id-Version: PACKAGE VERSION
Report-Msgid-Bugs-To: sssd-devel@lists.fedorahosted.org
POT-Creation-Date: 2020-06-17 22:51+0200
PO-Revision-Date: 2014-12-14 11:45+0000
Last-Translator: Copied by Zanata <copied-by-zanata@zanata.org>
Language-Team: Hungarian (http://www.transifex.com/projects/p/sssd/language/hu/)
Language: hu
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Plural-Forms: nplurals=2; plural=(n != 1);
X-Generator: Zanata 4.6.2
 , a gyorsítótárazott jelszó lejár ekkor:  Időbélyegek a hibakeresési kimenetben Hiba lépett fel, de nem érhetőek el részletek. Azonosítva gyorsítótárazott adatbázisból A bejelentkezés tiltott eddig: Azonosító-kiszolgáló Időtúllépés azonosításkor Azonosítók gyorsítótárazása offline használathoz Nem áll rendelkezésre információ a felhasználóról
 Nem lehet beállítani az alapértékeket
 Felhasználó könyvtárának létrehozása, ha nem létezik Jelenlegi jelszó: Ne törölje a saját könyvtárat és a helyi levelezést Bejegyzés-gyorsítótár érvényessége (másodperc) A CA tanusítványokat tartalmazó fájl Nem a felhasználó tulajdonában lévő fájlok törlése Teljes név GECOS attribútum Csoport neve Csoport jelszava Csoportok SSSD által figyelmen kívül hagyott csoportok Felhasználó hozzáadása a következő csoportokhoz Saját könyvtár Hány sikertelen bejelentkezés engedélyezett offline állapotban IPA kliens hosztneve IPA-tartomány IPA kiszolgáló címe Belső hiba történt, nem lehetett eltávolítani a felhasználót.
 Kerberos-tartomány Kerberos-kiszolgáló címe Felhasználó programjainak kilövése az eltávolítás előtt A kapcsolódási próbálkozás időtartama Fiók zárolása Bejelentkező shell Legnagyobb felhasználói azonosító Legkisebb felhasználói azonosító Ne hozza létre a felhasználó könyvtárát Új jelszó: Elfogyott a memória
 A jelszó megváltoztatása nem sikerült. A jelszava lejárt, változtass meg most. A jelszó root általi visszaállítása nem támogatott. Jelszó:  A jelszavak nem egyeznek Jelszó mégegyszer:  TLS tanusítvány ellenőrzése TLS megkövetelése ID keresésekor Elindítandó SSSD szolgáltatások Az SSSD nem root-ként fut. Szerver üzenete: Shell attribútum Mikroszekundum pontosságú időbélyegek Adja meg a törlendő felhasználót
 Adja meg a módosítandó felhasználót
 A rendszer nem érhető el, a jelszó megváltoztatása nem lehetséges A csoport GID-je Felhasználó GID-je Az LDAP szerveren használt séma-típus, rfc2307 A felhasználó UID-je Alapértelmezett LDAP alap-DN-je Az alapértelmezett bind DN A megadott UID kívül esik a megengedett tartományon
 Tranzakcióhiba történt, nem lehetett létrehozni a felhasználót.
 Tranzakcióhiba történt, a felhasználó nem módosítható.
 Fiók feloldása A felhasználó könyvtára már létezik, a skel könyvtár tartalmát nem másolom bele
 SSSD által figyelmen kívül hagyott felhasználók ldap_uri, az LDAP szerver URI-ja memberOf attribútum 