??    }        ?   ?      ?
  *   ?
  2  ?
  &   ?          -  /   F  %   v  5   ?  4   ?  %        -     B     X     w     ?     ?     ?     ?     ?  %         &     <     T  0   l  '   ?  )   ?  !   ?          .  )   M     w  -   ?  "   ?     ?     ?     ?  !        >  L   T  1   ?  #   ?     ?          1     M  0   R     ?     ?     ?     ?     ?               3  
   D     O     h     ?     ?  '   ?     ?      ?  )     ,   ,  '   Y  $   ?  1   ?     ?  *   ?  ,        G     b     ?     ?     ?  E   ?            4  *     _  *   c     ?  ?   ?  	   ?  %   ?     ?  %   ?      ?       +   ,     X     j  ?   w  ?        ?  (   ?  ?   ?  #   ?     ?  V    ?   p  ?   ?     ?      ?      ?      ?      !  0   $!     U!  .   f!  
  ?!  0  ?"  ?   ?$  U   U%  5   ?%     ?%     ?%  )   &  (   >&     g&     s&  	   {&  ?   ?&  :   ?&  ?   '  2   ?(  o  2)  1   ?+  3   ?+  &   ,  1   /,  '   a,  3   ?,  6   ?,  3   ?,     (-  "   F-  *   i-     ?-  #   ?-  %   ?-     ?-     .  *   0.  H   [.  %   ?.  &   ?.  $   ?.  7   /  =   N/  2   ?/  )   ?/  $   ?/  &   0  3   50     i0  :   }0  -   ?0  	   ?0  *   ?0  *   1  0   F1     w1  v   ?1  =   	2  7   G2  &   2  '   ?2     ?2     ?2  ?   ?2  *   33  -   ^3  !   ?3  %   ?3     ?3  "   ?3      4     84     V4  ,   j4  '   ?4     ?4  #   ?4  :   ?4     /5  /   B5  <   r5  A   ?5  /   ?5  !   !6  :   C6  &   ~6  5   ?6  3   ?6  $   7  .   47     c7     w7  !   ?7  L   ?7      8     8  ?  +8     ?;  -   ?;     ?;  ?   <  
   =  -   =     A=  *   a=  $   ?=     ?=  5   ?=     >     ">  ?   6>  ?   ?>     ??  0   ??  V   @  7   WA  &   ?A  ?  ?A  ?   =C  ?   ?C     ?D  4   ?D     E     /E     LE  -   _E     ?E  1   ?E  t  ?E  r  CG  ?   ?I  v   XJ  J   ?J  &   K      AK  6   bK  0   ?K     ?K     ?K     ?K  G   L  B   IL        S          U           9   /   @   H   t          a   i             A   V   8       W      I       >   u   0   G       ;   y   2           _   w       ^   K   l           B      q   1               f       (   o   m   c   
          T          !   O   -   L   E           R   ]      P   7            C       N   %                  )   ,       #            5      Y   &   .      Z   s              j           F   }   J   4      z          M   ?      \          e   h       r           +   [   3       v   p   `          $   D   :   X   '   *   |   k   g             x   	       =   {               <   "      Q   b   6   n   d        '%s' is not a valid value for the property ---[ Property menu ]---
set      [<value>]               :: set new value
add      [<value>]               :: add new option to the property
change                           :: change current value
remove   [<index> | <option>]    :: delete the value
describe                         :: describe property
print    [setting | connection]  :: print property (setting/connection) value(s)
back                             :: go to upper level
help/?   [<command>]             :: print this help or command description
quit                             :: exit nmcli
 802.1X supplicant configuration failed 802.1X supplicant disconnected 802.1X supplicant failed 802.1X supplicant took too long to authenticate A dependency of the connection failed A problem with the RFC 2684 Ethernet over ADSL bridge A secondary connection of the base connection failed Allowed values for '%s' property: %s
 AutoIP service error AutoIP service failed AutoIP service failed to start Available properties: %s
 Carrier/link changed DCB or FCoE setup failed DHCP client error DHCP client failed DHCP client failed to start Device disconnected by user or client Device is now managed Device is now unmanaged Enter connection type:  Error: <setting>.<property> argument is missing. Error: failed to set '%s' property: %s
 Error: invalid <setting>.<property> '%s'. Error: invalid property '%s': %s. Error: invalid property: %s
 Error: invalid property: %s%s
 Error: missing setting for '%s' property
 Error: property %s
 Failed to register with the requested network Failed to select the specified APN GROUP GSM Modem's SIM PIN required GSM Modem's SIM PUK required GSM Modem's SIM card not inserted GSM Modem's SIM wrong IP configuration could not be reserved (no available address, timeout, etc.) InfiniBand device does not support connected mode Modem failed or no longer available Modem initialization failed Modem now ready and available ModemManager is unavailable NAME Necessary firmware for the device may be missing Network registration denied Network registration timed out NetworkManager went to sleep No carrier could be established No dial tone No reason given Not searching for networks PIN check failed PPP failed PPP service disconnected PPP service failed to start Property name?  SIM PIN was incorrect Secrets were required, but not provided Setting name?  Shared connection service failed Shared connection service failed to start The Bluetooth connection failed or timed out The IP configuration is no longer valid The Wi-Fi network could not be found The device could not be readied for configuration The device was removed The device's active connection disappeared The device's existing connection was assumed The dialing attempt failed The dialing request timed out The line is busy The modem could not be found The supplicant is now available Type 'describe [<setting>.<prop>]' for detailed property description. Unknown Unknown error Usage: nmcli connection modify { ARGUMENTS | help }

ARGUMENTS := [id | uuid | path] <ID> ([+|-]<setting>.<property> <value>)+

Modify one or more properties of the connection profile.
The profile is identified by its name, UUID or D-Bus path. For multi-valued
properties you can use optional '+' or '-' prefix to the property name.
The '+' sign allows appending items instead of overwriting the whole value.
The '-' sign allows removing selected items instead of the whole value.

Examples:
nmcli con mod home-wifi wifi.ssid rakosnicek
nmcli con mod em1-1 ipv4.method manual ipv4.addr "192.168.1.2/24, 10.10.1.5/8"
nmcli con mod em1-1 +ipv4.dns 8.8.4.4
nmcli con mod em1-1 -ipv4.dns 1
nmcli con mod em1-1 -ipv6.addr "abbe::cafe/56"
nmcli con mod bond0 +bond.options mii=500
nmcli con mod bond0 -bond.options downdelay

 VPN You may edit the following properties: %s
 [NM property description] add [<value>]  :: append new value to the property

This command adds provided <value> to this property, if the property is of a container type. For single-valued properties the property value is replaced (same as 'set').
 connected connecting (checking IP connectivity) connecting (configuring) connecting (getting IP configuration) connecting (need authentication) connecting (prepare) connecting (starting secondary connections) connection failed deactivating describe  :: describe property

Shows property description. You can consult nm-settings(5) manual page to see all NM settings and properties.
 describe [<setting>.<prop>]  :: describe property

Shows property description. You can consult nm-settings(5) manual page to see all NM settings and properties.
 disconnected don't know how to get the property value goto <setting>[.<prop>] | <prop>  :: enter setting/property for editing

This command enters into a setting or property for editing it.

Examples: nmcli> goto connection
          nmcli connection> goto secondaries
          nmcli> goto ipv4.addresses
 invalid prefix '%s'; <1-%d> allowed invalid priority map '%s' nmcli can accepts both direct JSON configuration data and a file name containing the configuration. In the latter case the file is read and the contents is put into this property.

Examples: set team.config { "device": "team0", "runner": {"name": "roundrobin"}, "ports": {"eth1": {}, "eth2": {}} }
          set team.config /etc/my-team.conf
 print [all]  :: print setting or connection values

Shows current property or the whole connection.

Example: nmcli ipv4> print all
 print [property|setting|connection]  :: print property (setting, connection) value(s)

Shows property value. Providing an argument you can also display values for the whole setting or connection.
 property invalid property invalid (not enabled) property is empty property is invalid property is missing property is not specified and neither is '%s:%s' property missing property value '%s' is empty or too long (>64) remove <setting>[.<prop>]  :: remove setting or reset property value

This command removes an entire setting from the connection, or if a property
is given, resets that property to the default value.

Examples: nmcli> remove wifi-sec
          nmcli> remove eth.mtu
 remove [<value>|<index>|<option name>]  :: delete the value

Removes the property value. For single-valued properties, this sets the
property back to its default value. For container-type properties, this removes
all the values of that property, or you can specify an argument to remove just
a single item or option. The argument is either a value or index of the item to
remove, or an option name (for properties with named options).

Examples: nmcli ipv4.dns> remove 8.8.8.8
          nmcli ipv4.dns> remove 2
          nmcli bond.options> remove downdelay

 set [<setting>.<prop> <value>]  :: set property value

This command sets property value.

Example: nmcli> set con.id My connection
 set [<value>]  :: set new value

This command sets provided <value> to this property
 setting this property requires non-zero '%s' property teamd control failed the property can't be changed this property cannot be empty for '%s=%s' this property is not allowed for '%s=%s' unavailable unknown unmanaged use 'goto <setting>' first, or 'describe <setting>.<property>'
 use 'goto <setting>' first, or 'set <setting>.<property>'
 Project-Id-Version: network-manager
Report-Msgid-Bugs-To: 
POT-Creation-Date: 2019-05-28 14:23+0200
PO-Revision-Date: 2016-01-29 11:29+0100
Last-Translator: GunChleoc <fios@foramnagaidhlig.net>
Language-Team: Fòram na Gàidhlig
Language: gd
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Plural-Forms: nplurals=4; plural=(n==1 || n==11) ? 0 : (n==2 || n==12) ? 1 : (n > 2 && n < 20) ? 2 : 3;
X-Generator: Virtaal 0.7.1
X-Launchpad-Export-Date: 2016-01-28 16:48+0000
 chan eil "%s" 'na luach dligheach airson na buaidh ---[ Clàr-taice na buaidh ]---
set      [<luach>]                :: suidhich luach ùr
add      [<luach>]                :: cuir an roghainn ùr ris a' bhuadh
change                            :: atharraich an luach làithreach
remove   [<inneacs> | <roghainn>] :: sguab às an luach
describe                          :: mìnich a' bhuadh
print    [setting | connection]   :: seall luach(an) na buaidh (roghainn/ceangal)
back                              :: rach gu leibheil nas àirde
help/?   [<àithne>]               :: seall a' chobhair seo no tuairisgeul na h-àithne
quit                              :: fàg nmcli
 Dh'fhàillig le rèiteachadh a' 802.1X supplicant Chaidh an ceangal aig 802.1X supplicant a bhriseadh Dh'fhàillig leis a' 802.1X supplicant Thug e ro fhada an 802.1X supplicant a dhearbhadh Dh'fhàillig eisimeileachd a' cheangail Duilgheadas le RFC 2684 Ethernet thar drochaid ADSL Dh'fhàillig le ceangal dàrnach a' cheangail thùsail Luachan a tha ceadaichte airson na buaidh "%s": %s
 Mearachd na seirbheise AutoIP Dh'fhàillig an t-seirbheis AutoIP Cha deach le seirbheis AutoIP tòiseachadh Buadhan ri am faighinn: %s
 Dh'atharraich an giùlanair/ceangal Dh'fhàillig suidheachadh DCB no FCoE Mearachd a' chliaint DHCP Dh'fhàillig an cliant DCHP Dh'fhàillig tòiseachadh a' chliaint DHCP Chaidh ceangal an uidheim a bhriseadh le cleachdaiche no leis a' chliant Tha an t-uidheam fo stiùireadh a-nis Tha an t-uidheam gun stiùireadh a-nis Cuir a-steach seòrsa a' cheangail:  Mearachd: tha argamaid a dhìth air <roghainn>.<buadh>. Mearachd: cha deach leinn a' bhuadh "%s" a shuidheachadh: %s
 Mearachd: <roghainn>.<buadh> mhì-dhligheach "%s". Mearachd: buadh mhì-dhligheach "%s": %s. Mearachd: buadh mhì-dhligheach: %s
 Mearachd: buadh mhì-dhligheach: %s%s
 Mearachd: tha roghainn a dhìth air a' bhuadh "%s"
 Mearachd: buadh %s
 Cha deach leinn clàradh leis an lìonra a chaidh iarraidh Cha deach leinn an APN sònraichte a thaghadh BUIDHEANN Tha feum air PIN an t-SIM aig a' GSM Modem Tha feum air PUK an t-SIM aig a' GSM Modem Cha deach cairt SIM a' GSM Modem a chur a-steach Tha SIM a' GSM Modem cearr Tha b' urrainn dhuinn rèiteachadh an IP a ghlèidheadh (chan eil seòladh ri làimh, dh'fhalbh an ùine air is msaa.) Cha chuir an t-uidheam InfiniBand taic dhan mhodh cheangailte Dh'fhàillig am modem no chan eil e ri làimh tuilleadh Dh'fhàillig le tòiseachadh a' mhodem Tha am modem deiseil 's ri làimh a-nis Chan eil ModemManager ri làimh AINM Dh'fhaoidte gu bheil firmware riatanach a dhìth air an uidheam Chaidh clàradh an lìonraidh a dhiùltadh Dh'fhalbh an ùine air clàradh an lìonraidh Chaidh an NetworkManager a chadal Cha deach giùlanair a stèidheachadh Chan eil seirm daithealaidh ann Cha deach adhbhar a thoirt seachad Chan eil lìonraidhean 'gan lorg Dh'fhàillig dearbhadh a' PIN Dh'fhàillig am PPP Chaidh ceangal na seirbheise PPP a bhriseadh Cha deach le seirbheis PPP tòiseachadh Ainm na buaidh?  Cha robh PIN an t-SIM mar bu chòir Chaidh rùintean-dìomhair iarraidh ach cha deach an solar Ainm na roghainn?  Dh'fhàillig seirbheis a' cheangail cho-roinnte Dh'fhàillig tòiseachadh seirbheis a' cheangail cho-roinnte Dh'fhàillig leis a' cheangal bluetooth no dh'fhalbh an ùine air Chan eil rèiteachadh an IP dligheach tuilleadh Cha deach an lìonra Wi-Fi a lorg Cha deach leinn an t-uidheam ullachadh airson rèiteachadh Chaidh an t-uidheam a thoirt air falbh Rach ceangal gnìomhach an uidheim a-mach à sealladh Bhathar an dùil air ceangal làithreach an uidheim Dh'fhàillig oidhirp an daithealaidh Dh'fhalbh an ùine air an iarrtas daithealaidh Tha an loidhne rang Cha deach am modem a lorg Tha an supplicant ri làimh a-nis Sgrìobh 'describe [<roghainn>.<buadh>]' airson mion-fhiosrachadh na buaidh. Chan eil fhios Mearachd nach aithne dhuinn Cleachdadh: nmcli connection modify { ARGAMAIDEAN | help }

ARGAMAIDEAN := [id | uuid | slighe] <ID> ([+|-]<roghainn>.<buadh> <luach>)+

Atharraich buadh no dhà aig pròifil a' cheangail.
Thèid a' phròifil aithneachadh le a h-ainm, UUID no slighe D-Bus. airson buadhan
le iomadh luach, faodaidh tu "+" or "-" a chur ri toiseach ainm na buaidh air do thoil.
Leigidh an samhla "+" leat gun cuir thu nithean ris seach sgrìobhadh thairis air an luach iomlan.
Leigidh an samhla "-" leat gun doir thu nithean sònraichte air falbh seach sgrìobhadh thairis air an luach iomlan.

Mar eisimpleir:
nmcli con mod home-wifi wifi.ssid rakosnicek
nmcli con mod em1-1 ipv4.method manual ipv4.addr "192.168.1.2/24, 10.10.1.5/8"
nmcli con mod em1-1 +ipv4.dns 8.8.4.4
nmcli con mod em1-1 -ipv4.dns 1
nmcli con mod em1-1 -ipv6.addr "abbe::cafe/56"
nmcli con mod bond0 +bond.options mii=500
nmcli con mod bond0 -bond.options downdelay

 VPN Faodaidh tu na buadhan seo a dheasachadh: %s
 [tuairisgeul buaidh NM] add [<luach>]  :: cuir luach ùr ris a' bhuadh

Cuiridh an àithne seo an <luach> a chaidh a shònrachadh ris a' bhuadh seo ma tha
a' bhuadh 'na soitheach. Airson buadhan le luach a-mhàin, thèid luach na buaidh
a chur an àite (mar a nì "set").
 ceangailte 'ga cheangal (a' dearbhadh comas-ceangail IP) 'ga cheangal ('ga rèiteachadh) 'ga cheangal (a' faighinn rèiteachadh IP) 'ga cheangal (feumach air dearbhadh) 'ga cheangal ('ga ullachadh) 'ga cheangal (a' tòiseachadh ceanglaichean dàrnach) dh'fhàillig leis a' cheangal 'ga chur à gnìomh describe  :: mìnich a' bhuadh

Seall tuairisgeul na buaidh. Thoir sùil air duilleag an leabhair-mìneachaidh aig
nm-settings(5) gus a h-uile roghainn is buadh aig NM a shealltainn.
 describe [<roghainn>.<buadh>]  :: mìnich a' bhuadh

Seall tuairisgeul na buaidh. Thoir sùil air duilleag an leabhair-mìneachaidh aig
nm-settings(5) gus a h-uile roghainn is buadh aig NM a shealltainn.
 air a dhì-cheangal chan eil fhios mar a gheibh sinn luach na buaidh goto <roghainn>[.<buadh>] | <buadh>     :: rach a-steach dha roghainn/buadh
                                           a chum deasachaidh

Bheir an àithne seo gu roghainn no buadh thu ach an deasaich thu i.

Mar eisimpleir: nmcli> goto connection
                nmcli connection> goto secondaries
                nmcli> goto ipv4.addresses
 ro-leasachan mì-dhligheach "%s"; tha <1-%d> ceadaichte mapa prìomhachais "%s" mì-dhligheach Gabhaidh nmcli an dà chuid ri dàta rèiteachaidh JSON dìreach agus ainm faidhle sa bheil an rèiteachadh. Mas e ainm faidhle a th' ann, thèid am faidhle a leughadh agus an t-susbaint aige a chur dhan bhuadh seo.

Mar eisimpleir: set team.config { "device": "team0", "runner": {"name": "roundrobin"}, "ports": {"eth1": {}, "eth2": {}} }
                set team.config /etc/my-team.conf
 print [all]  :: seall fiosrachadh roghainn no luachan a' cheangail

Seallaidh seo a' bhuadh làithreach no an ceangal air fad.

Mar eisimpleir: nmcli ipv4> print all
 print [buadh|roghainn|ceangal]  :: seall luach(an) buaidh (roghainn, ceangal)

Seallaidh seo luach na buaidh. Ma bheir thu seachad argamaid, 's urrainn dhut luachan
a shealltainn airson na roghainn no a' cheangail gu lèir cuideachd.
 buadh mhì-dhligheach chan eil a' bhuadh dligheach (chan eil i gnìomhach) tha a' bhuadh falamh tha a' bhuadh mì-dhligheach tha buadh a dhìth cha deach a' bhuadh no "%s:%s" a shònrachadh buadh a dhìth tha luach na buaidh "%s" falamh no ro fhada (>64) remove <roghainn>[.<buadh>]             :: thoir roghainn air falbh no
                                           ath-shuidhich luach buaidhe

Bheir an àitne seo air falbh roghainn shlàn on cheangal, no ma chaidh buadh a thoirt
seachad, ath-shuidhichidh e a' bhuadh sin air an luach tùsail.

Mar eisimpleir: nmcli> remove wifi-sec
                nmcli> remove eth.mtu
 remove [<luach>|<inneacs>|<ainm_buaidh>]  :: sguab às an luach

Bheir seo luach na buaidh air falbh. Airson buadhan le luach a-mhàin, suidhichidh
seo a' bhuaidh air a luach tùsail. Airson buadhan a tha 'nan soithichean, bheir seo
air falbh gach luach na buaidh no 's urrainn dhut , argamaid a shònrachadh gus nì
no roghainn a-mhàin a thoirt air falbh. Tha an argamaid 'na luach no inneacs an nì
ri thoirt air falbh no ainm roghainne (airson buadhan le roghainnean ainmichte).

Mar eisimpleir: nmcli ipv4.dns> remove 8.8.8.8
                nmcli ipv4.dns> remove 2
                nmcli bond.options> remove downdelay

 set [<roghainn>.<buadh> <luach>]        :: suidhich luach na buaidh

Suidhichidh an àithne seo luach buaidh.

Mar eisimpleir: nmcli> set con.id An ceangal agam
 set [<luach>]  :: suidhich luach ùr

Suidhichidh an àithne seo a' bhuadh seo air an <luach> a chaidh a shònrachadh
 feumaidh tu buadh "%s" nach eil na neoni gus a' bhuadh seo a shuidheachadh Dh'fhàillig an t-uidheam-smachd teamd cha ghabh a' bhuadh atharrachadh chan fhaod a' bhuadh seo a bhith falamh airson "%s=%s" chan eil a' bhuadh seo ceadaichte airson "%s=%s" chan eil e ri fhaighinn chan eil fhios gun stiùireadh cleachd "goto <roghainn>" an toiseach no "describe <roghainn>.<buadh>"
 cleachd "goto <roghainn>" an toiseach no "set <roghainn>.<buadh>"
 