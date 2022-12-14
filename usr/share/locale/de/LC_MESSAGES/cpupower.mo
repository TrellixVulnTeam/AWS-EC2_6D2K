??    1      ?  C   ,      8  G   9  {   ?  M   ?  C   K  ?   ?  w     0   ?  @   ?  2     .   8  Q   g  R   ?  ?     @   ?  >   ?  R   	  =   q	  M   ?	  ?   ?	  Q   ?
  C   ?
  1   "     T     t     ?     ?  -   ?     ?     ?       5   /     e     ?  ^   ?  7   ?  ?  "  g   ?  ?     	   ?  &   ?  Q   ?  U   '  ^   }     ?  9   ?     )  _   F  !   ?  e  ?  G   .  ?   v  p   ?  >   p  r   ?     "  1   ?  D   ?  8     4   R  N   ?  ?   ?  ?   ^  <     ?   Y  |   ?  K   Z  p   ?  ?     U   ?  C   7  ?   {     ?     ?     ?     ?  0        G  -   V  -   ?  5   ?  0   ?       h     K   ?  d  ?     9  ?   ?  
   Q      \   ?   |   ?   ?   ~   >!     ?!  J   ?!  $   "  s   A"  $   ?"               %         $                   '   &   	       ,                      )                        (   
                     *              +                   -                !                 .   "   1      0         /      #              minimum CPU frequency  -  maximum CPU frequency  -  governor
   -a, --affected-cpus  Determines which CPUs need to have their frequency
                       coordinated by software *
   -d FREQ, --min FREQ      new minimum CPU frequency the governor may select
   -d, --driver         Determines the used cpufreq kernel driver *
   -f FREQ, --freq FREQ     specific frequency to be set. Requires userspace
                           governor to be available and loaded
   -f, --freq           Get frequency the CPU currently runs at, according
                       to the cpufreq core *
   -g GOV, --governor GOV   new cpufreq governor
   -g, --governors      Determines available cpufreq governors *
   -h, --help               Prints out this screen
   -h, --help           Prints out this screen
   -l, --hwlimits       Determine the minimum and maximum CPU frequency allowed *
   -m, --human          human-readable output for the -f, -w, -s and -y parameters
   -o, --proc           Prints out information like provided by the /proc/cpufreq
                       interface in 2.4. and early 2.6. kernels
   -p, --policy         Gets the currently used cpufreq policy *
   -r, --related            Switches all hardware-related CPUs
   -r, --related-cpus   Determines which CPUs run at the same hardware frequency *
   -s, --stats          Shows cpufreq statistics if available
   -u FREQ, --max FREQ      new maximum CPU frequency the governor may select
   -w, --hwfreq         Get frequency the CPU currently runs at, by reading
                       it from hardware (only available to root) *
   -y, --latency        Determines the maximum latency on CPU frequency changes *
   CPUs which need to have their frequency coordinated by software:    CPUs which run at the same hardware frequency:    available cpufreq governors:    available frequency steps:    cpufreq stats:    current CPU frequency is    current policy: frequency should be within    driver: %s
   hardware limits:    maximum transition latency:    no or unknown cpufreq driver is active on this CPU
  (asserted by call to hardware)  and  At least one parameter out of -f/--freq, -d/--min, -u/--max, and
-g/--governor must be passed
 Couldn't count the number of CPUs (%s: %s), assuming 1
 Error setting new values. Common errors:
- Do you have proper administration rights? (super-user?)
- Is the governor you requested available and modprobed?
- Trying to set an invalid policy?
- Trying to set a specific frequency, but userspace governor is not available,
   for example because of hardware which cannot be set to a specific frequency
   or because the userspace governor isn't loaded?
 For the arguments marked with *, omitting the -c or --cpu argument is
equivalent to setting it to zero
 If no argument or only the -c, --cpu parameter is given, debug output about
cpufreq is printed which is useful e.g. for reporting bugs.
 Options:
 Report errors and bugs to %s, please.
 The argument passed to this tool can't be combined with passing a --cpu argument
 The governor "%s" may decide which speed to use
                  within this range.
 You can't specify more than one --cpu parameter and/or
more than one output-specific argument
 analyzing CPU %d:
 couldn't analyze CPU %d as it doesn't seem to be present
 invalid or unknown argument
 the -f/--freq parameter cannot be combined with -d/--min, -u/--max or
-g/--governor parameters
 wrong, unknown or unhandled CPU?
 Project-Id-Version: cpufrequtils 006
Report-Msgid-Bugs-To: 
POT-Creation-Date: 2011-03-08 17:03+0100
PO-Revision-Date: 2009-08-08 17:18+0100
Last-Translator:  <linux@dominikbrodowski.net>
Language-Team: NONE
Language: 
MIME-Version: 1.0
Content-Type: text/plain; charset=ISO-8859-1
Content-Transfer-Encoding: 8bit
Plural-Forms: nplurals=2; plural=(n != 1);
           minimale CPU-Taktfreq. -  maximale CPU-Taktfreq. -  Regler  
   -a, --affected-cpus  Findet heraus, von welchen CPUs die Taktfrequenz durch
                       Software koordiniert werden muss *
   -d FREQ, --min FREQ      neue minimale Taktfrequenz, die der Regler
                           ausw?hlen darf
   -d, --driver         Findet den momentanen Treiber heraus *
   -f FREQ, --freq FREQ     setze exakte Taktfrequenz. Ben?tigt den Regler
                           'userspace'.
   -f, --freq           Findet die momentane CPU-Taktfrquenz heraus (nach
                       Meinung des Betriebssystems) *
   -g GOV, --governors GOV  wechsle zu Regler GOV
   -g, --governors      Erzeugt eine Liste mit verf?gbaren Reglern *
   -h, --help               Gibt diese Kurz?bersicht aus
   -h, --help           Gibt diese Kurz?bersicht aus
   -l, --hwlimits       Findet die minimale und maximale Taktfrequenz heraus *
   -m, --human          Formatiert Taktfrequenz- und Zeitdauerangaben in besser
                       lesbarer Form (MHz, GHz; us, ms)
   -o, --proc           Erzeugt Informationen in einem ?hnlichem Format zu dem
                       der /proc/cpufreq-Datei in 2.4. und fr?hen 2.6.
                       Kernel-Versionen
   -p, --policy         Findet die momentane Taktik heraus *
   -r, --related            Setze Werte f?r alle CPUs, deren Taktfrequenz
                           hardwarebedingt identisch ist.
   -r, --related-cpus   Findet heraus, welche CPUs mit derselben physikalischen
                       Taktfrequenz laufen *
   -s, --stats          Zeigt, sofern m?glich, Statistiken ?ber cpufreq an.
   -u FREQ, --max FREQ      neue maximale Taktfrequenz, die der Regler
                           ausw?hlen darf
   -w, --hwfreq         Findet die momentane CPU-Taktfrequenz heraus
                       (verifiziert durch Nachfrage bei der Hardware)
                       [nur der Administrator kann dies tun] *
   -y, --latency        Findet die maximale Dauer eines Taktfrequenzwechsels heraus *
   Die Taktfrequenz folgender CPUs werden per Software koordiniert:    Folgende CPUs laufen mit der gleichen Hardware-Taktfrequenz:    m?gliche Regler:    m?gliche Taktfrequenzen:    Statistik:   momentane Taktfrequenz ist    momentane Taktik: die Frequenz soll innerhalb    Treiber: %s
   Hardwarebedingte Grenzen der Taktfrequenz:    Maximale Dauer eines Taktfrequenzwechsels:    kein oder nicht bestimmbarer cpufreq-Treiber aktiv
   (verifiziert durch Nachfrage bei der Hardware)  und  Es muss mindestens ein Parameter aus -f/--freq, -d/--min, -u/--max oder
-g/--governor angegeben werden.
 Konnte nicht die Anzahl der CPUs herausfinden (%s : %s), nehme daher 1 an.
 Beim Einstellen ist ein Fehler aufgetreten. Typische Fehlerquellen sind:
- nicht ausreichende Rechte (Administrator)
- der Regler ist nicht verf?gbar bzw. nicht geladen
- die angegebene Taktik ist inkorrekt
- eine spezifische Frequenz wurde angegeben, aber der Regler 'userspace'
  kann entweder hardwarebedingt nicht genutzt werden oder ist nicht geladen
 Bei den mit * markierten Parametern wird '--cpu 0' angenommen, soweit nicht
mittels -c oder --cpu etwas anderes angegeben wird
 Sofern kein anderer Parameter als '-c, --cpu' angegeben wird, liefert dieses
Programm Informationen, die z.B. zum Berichten von Fehlern n?tzlich sind.
 Optionen:
 Bitte melden Sie Fehler an %s.
 Diese Option kann nicht mit der --cpu-Option kombiniert werden
   liegen. Der Regler "%s" kann frei entscheiden,
                    welche Taktfrequenz innerhalb dieser Grenze verwendet wird.
 Man kann nicht mehr als einen --cpu-Parameter und/oder mehr als einen
informationsspezifischen Parameter gleichzeitig angeben
 analysiere CPU %d:
 Konnte nicht die CPU %d analysieren, da sie (scheinbar?) nicht existiert.
 unbekannter oder falscher Parameter
 Der -f bzw. --freq-Parameter kann nicht mit den Parametern -d/--min, -u/--max
oder -g/--governor kombiniert werden
 unbekannte oder nicht regelbare CPU
 