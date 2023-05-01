
# LISEZ MOI

Au départ pensé pour un apprentissage personnel et une recherche rapide par mots clés, cette page à vocation à faire une (nouvelle) liste/description des outils livrés dans Kali Linux.  

Peut être utile (ou pas) aux débutants qui, comme moi, ne les connaissent pas encore et souhaitent sélectionner l'outil adéquat pour un besoin donné.  
Le descriptif n'est pas exhaustif et contient sûrement des erreurs. Auquel cas, tous vos retours sont les bienvenus !  

Les applications sont énumérées selon la méthode de classement Kali Linux 2022.4 (2023).  

# 01 - RECUPERATION D'INFORMATIONS

## ANALYSE DNS

- __dnsenum__

> . outil de récupération d'informations relatives aux noms de domaine  
> . découverte de sous domaines par le biais de google  
> . attaque de base brute force DNS par le biais de `DNSEnum`  
> . alimantation de son dictionnaire brut force DNS

- __dnsrecon__

> . vérification de certains enregistrements de cache du serveur DNS  
> . énumération des enregistrements DNS généraux pour un domaine donné  
> . vérification de tous les enregistrements NS pour les transferts de zone  
> . vérification de la résolution des caractères génériques  
> . énumération commune des enregistrements SRV et une extension du domaine de premier niveau (TLD)  
> . vérification par brute force de certains enregistrements, sous-domaines et hôtes à partir d'un domaine et d'une liste de mots  
> . recherche d'enregistrement PTR pour une plage d'adresses IP ou CIDR donnée  
> . énumération de sous-domaines et d'hôtes via Google Dorks  

- __fierce__

> . scanneur semi-léger qui aide à localiser l'espace IP et les noms d'hôte non contigus par rapport à des domaines spécifiés  
> . Il est destiné spécifiquement à localiser des cibles probables à l'intérieur et à l'extérieur d'un réseau d'entreprise  

## ANALYSE OSINT

- __maltego__ (EC)

> . puissant outil d'investigation OSINT grâce à ses 30 patenaires  
> . mappage d'extraction de données de sources disparates  
> . analyse de liens sur jusqu'à 10.000 XNUMX entités sur un seul graphique  
> . possibilité de renvoyer jusqu'à 12 résultats par transformation  
> . inclusion de nœuds de collecte qui regroupent automatiquement les entités ayant des caractéristiques communes  
> . partage de graphiques en temps réel avec plusieurs analystes en une seule session  
> . larges options d'exportation de graphiques  

- __spiderfoot__ & __spiderfoot-cli__

> . outil de reconnaissance de cible de manière offensive  
> . plus de 200 modules pour assurer une extraction optimale des données  
> . récupération à partir de : IP, domaine/sous domaine, CIDR, ASN, mail, tél, nom utilisateur, nom de la personne, adresse bitcoin  
> . énumération/extraction d'hôtes/sous-domaines/TLD  
> . extraction d'adresse e-mail, de numéro de téléphone et de nom humain  
> . extraction d'adresses Bitcoin et Ethereum  
> . vérification de la sensibilité au piratage de sous-domaine  
> . transferts de zone DNS  
> . renseignements sur les menaces et requêtes de liste noire  
> . intégration API avec SHODAN, HaveIBeenPwned, GreyNoise, AlienVault, SecurityTrails, etc.  
> . énumération des comptes de médias sociaux  
> . énumération/grattage du bucket S3, Azure, Digitalocean  
> . géolocalisation IP  
> . scraping Web, analyse de contenu Web  
> . analyse de métadonnées d'images, de documents et de fichiers binaires  
> . recherches sur le dark web  
> . balayage de ports et capture de bannières  
> . recherches de violation de données  

- __theharvester__

> . outil de reconnaissance de cible de manière offensive
> . informations sur les mails  
> . informations sur les sous domaines  
> . informations sur les hôtes  
> . informations sur les noms des employés  
> . informations sur les ports ouverts et les bannières  

## ANALYSE ROUTE

- __netdiscover__

> . mapping de réseau qui permet de l'écoute passive et/ou active  
> . principalement développé pour les réseaux sans fil sans serveur dhcp  
> . peut aussi s'utiliser sur des réseaux hub/switchés  
> . peut détecter passivement les hôtes connectés ou les chercher en envoyant activement des requêtes ARP  
> . utilise la table OUI pour afficher le fabricant de chaque adresse MAC rencontrée  
> . si besoin : peut être une alternative à nmap  

- __netmask__

> . peut convertir les notations d'adresse et de masque réseau  
> . peut optimiser les masques pour générer la plus petite liste de règle  
> . permet de diviser un réseau avec un même adressage  
> . peut organiser les hôtes en groupe logique  
> . permet de décongestionner un réseau  

## ANALYSE SMB

- __enum4linux__

> . descendant de `enum.exe` (c++), outil puissant d'énumération d'informations systèmes Windows et Samba  
> . analyse des services et des ports pour LDAP(S), SMB, NetBIOS, MS-RPC  
> . analyse les noms NetBIOS et groupes de travail (par recherche inversée)  
> . vérification des dialectes SMB (SMBv1 uniquement ou SMBv1 et supérieur)  
> . vérifications des sessions RPC (vérifie si les identifiants fournis sont valides ou si une session nulle fonctionne)  
> . informations sur le domaine via LDAP (pour savoir si l'hôte est un DC parent ou enfant)  
> . informations sur le domaine via RPC (via SMB named pipe \pipe\lsarpc pour MS-RPC)  
> . informations sur le système d'exploitation via RPC (via SMB named pipe \pipe\srvsvc pour MS-RPC)  
> . utilisateurs, groupes, partages, stratégies, imprimantes, services via RPC  
> . utilisateurs, groupes et machines via le cycle RID  
> . renforcement brutal des noms de partages SMB  

- __nbtscan__

> . balayage des réseaux IP pour les informations de nommage NetBIOS  

- __smbmap__

> . énumérateur des lecteurs de partages Samba sur l'ensemble d'un domaine  

## ANALYSE SMTP

- __swaks__

> . principalement un outil de test SMTP ;  
> . géstion des extensions SMTP, TLS, authentification, pipelining, PROXY, PRDR et XCLIENT
Protocoles incluant SMTP, ESMTP et LMTP  
> . transports des sockets de domaine Internet (IPv4 et IPv6), domaine UNIX et des canaux vers les processus générés  
> . configuration entièrement scriptable  

## ANALYSE SSL

- __ssldump__

> . analyseur de protocole réseau SSL/TLS  
> . identification des connexions TCP sur l'interface réseau choisie et tente de les interpréter comme du trafic SSLv3/TLS  
> . peut décoder les enregistrements et les afficher sous forme de texte sur stdout  
> . peut déchiffrer les connexions et afficher le trafic de données application si fourni avec le matériel de chiffrement approprié  
> . inclus également une option de sortie JSON et prend en charge JA3 et IPv6  

- __sslh__

> . un multiplexeur ssl/ssh sur le port 443  
> . depuis la version 1.10 il supporte aussi le multiplexage de openvpn, tinc et xmpp (jabber)  
> . limité par les réseaux qui filtrent avec une liste blanche d'adresse IP  

- __sslscan__

> . outil de détection de la configuration SSL et des vulnérabilités associées  
> . mise en évidence des algorithmes de chiffrement SSLv2 et SSLv3 dans la sortie  
> . mise en évidence des algorithmes de chiffrement CBC sur SSLv3 (POODLE)  
> . mise en évidence des algorithmes de chiffrement 3DES et RC4 dans le résultat  
> . mise en évidence des algorithmes de chiffrement PFS+GCM comme étant bons dans le résultat  
> . vérification de la présence d'OpenSSL HeartBleed (CVE-2014-0160)  
> . signalisation des certificats expirés  
> . signalisation des clés DHE faibles avec OpenSSL >= 1.0.2  
> . support expérimental de Windows et OS X  
> . prise en charge de l'analyse des serveurs PostgreSQL  
> . prise en charge de StartTLS pour LDAP  

- __sslyze__

> . une bibliothèque Pyhton et un outil CLI rapide et puissant pour analyser SSl/TLS  
> . analyse de la configuration pour vérifier le paramètrage de cryptage  
> . analyse de la vulnérabilité aux attaques TLS connues  

## DETECTION DE IDS/IPS

- __lbd__

> . détecteur d'équilibrage de charge afin d'anticiper le cas échéant les problèmes de précisions des tests d'intrusion  
> . une bibliothèque de base de données intégrée légère et une API  
> . à mi-chemin entre les bases de données de paires clé/valeur (telles que berkley db ou tdb) et une base de données LDAP complète  

- __wafw00f__

> . identification et prise d'empreinte des produits WAF (Web Application Firewall)  

## EN DIRECT D'IDENTIFICATION D'HÔTE

- __arping__

> . outil de test de connectivité d'une machine connectée sur le même sous réseau par requête ARP  
> . semblable à la commande ping sauf que cette dernière envoie des requêtes ICMP  

- __fping__

> . outil qui permet de fournir en entrée une liste de plusieurs hôtes ou réseaux à analyser  
> . variante plus puissante de `ping` lors du ping de plusieurs hôtes  
> . permet la création de scripts  

- __hping3__

> . outil réseau capable d'envoyer des paquets TCP/IP personnalisés  
> . affichage des réponses cibles comme ping le fait avec des réponses ICMP  
> . gestion de la fragmentation, du corps et de la taille des paquets arbitraires  
> . peut être utilisé pour transférer des fichiers encapsulés sous des protocoles pris en charge  
> . test les règles de pare-feu  
> . balayage avancé des ports  
> . test les performances du réseau en utilisant différents protocoles, taille de paquet, TOS (type de service) et fragmentation  
> . découverte du chemin MTU  
> . transfert de fichiers entre des règles de pare-feu  
> . semblable à `traceroute` sous différents protocoles
> . utilisation similaire à `Firewalk`
> . empreinte digitale du système d'exploitation à distance  
> . audit de la pile TCP/IP  

- __masscan__

> . puissant scanner de port à l'échelle d'internet : transmet 10M de paquets/seconde à partir d'une seule machine  
> . utilisation (paramètre, sortie) similaire à celle de `nmap`  
> . en interne il utilise une transmission asynchrone similaire à `scanrand`  
> . attention, peut engendrer des DDoS sur le réseau et peut être bloqué par des sytèmes de protection IDS ou IPS  

- __thcping6__

> . boite à outil d'attaque IPv6 qui comprend de nombreux outils  

## NUMERISATION RESEAU

- __masscan__

> . puissant scanner de port à l'échelle d'internet : transmet 10M de paquets/seconde à partir d'une seule machine  
> . utilisation (paramètre, sortie) similaire à celle de `nmap`  
> . en interne il utilise une transmission asynchrone similaire à `scanrand`  
> . attention, peut engendrer des DDoS sur le réseau et peut être bloqué par des sytèmes de protection IDS ou IPS  

- __nmap__

> . puissant scanner de port qui permet d'analyser rapidement de grands réseaux et des hôtes uniques en utilisant des paquets IP bruts  
> . peut déterminer quels hôtes sont disponibles sur le réseau  
> . peut déterminer quels services (nom et version de l'application) ces hôtes offrent  
> . peut déterminer quel système d'exploitation et sa version l'hôte exécutent  
> . peut déterminer quel type de filtre/pare feu sont en cours d'utilisation  

## SNMP Analysis

- __onesixtyone__

> . scanner SNMP simple et rapide  
> . envoie des requêtes SNMP pour la valeur sysDescr de manière asynchrone  pour donner la description du logiciel exécuté  
> . heure d'envoi des requêtes réglagle par l'utilisateur  
> . balayage de tout un réseau de classe B en moins de 13 minutes  
> . peut être utilisé pour découvrir des périphériques répondant à des noms de communauté bien connus  
> . peut être pour monter une attaque par dictionnaire contre un ou plusieurs périphériques SNMP  

- __snmp-check__

> . vérification de l'état SNMP des hôtes spécifiés  
> . énumérateur d'informations matérielles, logiciels et réseaux de tous les appareils prenant en charge SNMP  

## _/_

- __amass__

> . outil pour effectuer une cartographie réseau des surfaces d'attaque  
> . permet la découverte d'actifs externes grâce à la collecte d'informations open source et de reconnaissance active  

- __dmitry__

> . outil de collecte d'informations open source  
> . peut être utilisé pour rechercher des sous-domaines de la cible  
> . peut être utilisé pour trouver les ports ouverts du système cible  
> . peut être utilisé pour effectuer une analyse TCP  
> . peut être utilisé avec le service netcraft  
> . peut être utilisé avec le service whois  
> . peut être utilisé pour obtenir des adresses e-mail associées au domaine de la cible  

- __ike-scan__

> . découverte et identification des hôtes IKE (serveurs VPN IPsec)  grâce à l'envoi de requêtes IKE ;  
> . peut déterminer quels hôtes exécutent IKE  
> . peut déterminer quelle implémentation IKE les hôtes utilisent  

- __legion (root)__

> . fork de Sparta de SECFORCE, c'est un outil de test de pénétration réseau super extensible et semi automatisé  
> . enregistrement automatique et en temps réel des résultats et tâches du projet  
> . détection automatique des CVE et des CPE  
> . fournit des estimations de l'achèvement des tâches  
> . prise en charge de la résolution de nom d'hôte  
> . analyse des hôtes vhosts/sni  

- __netdiscover__

> . mapping de réseau qui perlmet de l'écoute passive et/ou active  
> . principalement développé pour les réseaux sans fil sans serveur dhcp  
> . peut aussi s'utiliser sur des réseaux hub/switchés  
> . peut détecter passivement les hôtes connectés ou les chercher en envoyant activement des requêtes ARP  
> . utilise la table OUI pour afficher le fabricant de chaque adresse MAC rencontrée  
> . si besoin : peut être une alternative à nmap

- __recon-ng__

> . outil de collecte d'informations open source  
> . comprend un ensemble complet de modules de collecte d'informations  
> . fonctionne et agit comme une application Web/scanner de site Web  
> . peut trouver des failles dans le code des applications Web et des sites Web  
> . permet de trouver tous les sous-domaines d'un domaine cible  
> . peut être utilisé pour trouver les adresses IP de la cible  
> . peut être utilisé pour rechercher des injections SQL basées sur des erreurs  
> . peut être utilisé pour trouver des fichiers sensibles tels que robots.txt  
> . peut être utilisé pour détecter les systèmes de gestion de contenu (CMS) lors de l'utilisation d'une application Web cible  
> . les modules de scanner de ports détectent les ports fermés et ouverts  

# 02 - ANALYSE DE VULNERABILITE

## FUZZERS

- __spike__

> . kit de création de fuzzer  
> . attention, nécessite une solide connaissance de C  

## OUTILS VoIP

- __voiphopper__

> . outil de test de sécurité des infrastructures VoIP  
> . permet de détecter le VLAN associé aux flux téléphoniques puis de s’y insérer  
> . peut imiter le comportement des téléphones IP tester les risques au sein d'une infrastructure de réseau de téléphonie IP  

## __/__

- __nikto__

> . scanner de vulnérabilité qui analyse les serveurs web  
> . capture tous les cookies reçus  
> . test près de 6000 vulnérabilités CGI et fichiers dangereux  
> . vérifie l'obsolescence du serveur et ses composants logiciels  
> . recherche les répertoires pouvant contenir des informations sensibles  
> . supporte les connections SSL  

- __unix-privesc-check__

> . script shell qui s'exécute sur des systèmes Unix  
> . trouve des erreurs de configuration permettant une élévation des privilèges  
> . trouve des erreurs de configuration permettant d'accéder à des applications locales  

- __legion (root)__

> . fork de `Sparta` de SECFORCE, c'est un outil de test de pénétration réseau super extensible et semi automatisé  
> . enregistrement automatique et en temps réel des résultats et tâches du projet  
> . détection automatique des CVE et des CPE  
> . fournit des estimations de l'achèvement des tâches  
> . prise en charge de la résolution de nom d'hôte  
> . analyse des hôtes vhosts/sni  

- __nmap__

> . puissant scanner de port qui permet d'analyser rapidement de grands réseaux et des hôtes uniques en utilisant des paquets IP bruts  
> . peut déterminer quels hôtes sont disponibles sur le réseau  
> . peut déterminer quels services (nom et version de l'application) ces hôtes offrent  
> . peut déterminer quel système d'exploitation et sa version l'hôte exécutent  
> . peut déterminer quel type de filtre/pare feu sont en cours d'utilisation  

# 03 - APPLICATION WEB

## L'IDENTIFICATION DE VULNERABILITE DES WEB

- __cadaver__

> . client WebDAV en CLI pour Unix  
> . fonctionnement similaire au client standard BSD, ftp et au `smbclient` du projet Samba  
> . prend en charge le téléchargement de fichiers
> . prend en charge l'affichage à l'écran  
> . prend en charge les opérations d'espace de noms (déplacement et copie)  
> . prend en charge la création et la suppression de collections et les opérations de verrouillage  

- __davtest__

> . test des serveurs compatibles WebDAV  
> . tentative de création d'un nouveau répertoire (MKCOL)  
> . tentative de mettre des fichiers de test de divers langages de programmation (PUT)  
> . permet éventuellement de mettre des fichiers avec l'extension .txt, puis passez à l'exécutable (MOVE)  
> . permet éventuellement de mettre des fichiers avec l'extension .txt, puis de les copier dans un exécutable (COPY)  
> . vérifie si les fichiers ont été exécutés ou téléchargés correctement  
> . permet éventuellement de télécharger un fichier backdoor/shell pour les langages qui s'exécutent  
> . peut être utilisé pour placer un fichier arbitraire sur des systèmes distants  

- __nikto__

> . scanner de vulnérabilité qui analyse les serveurs web  
> . capture tous les cookies reçus  
> . test près de 6000 vulnérabilités CGI et fichiers dangereux  
> . vérifie l'obsolescence du serveur et ses composants logiciels  
> . recherche les répertoires pouvant contenir des informations sensibles  
> . supporte les connections SSL  

- __skipfish__

> . outil actif de reconnaissance de la sécurité des applications Web  
> . prépare un sitemap interactif du site ciblé en réalisant une analyse récursive et des sondes basées sur un dictionnaire  
> . très rapide en termes de requêtes tout en évitant d’utiliser trop le processeur  
> . outil de renseignement open source  
> . utilisé pour analyser les sites Web et les applications Web  
> . utilisé pour analyser les systèmes de gestion de contenu (CMS)  
> . peut trouver des vulnérabilités dans CMS  
> . dispose d'un grand nombre de modules  

- __wapiti__

> . outil qui permet de détecter la présence de failles courantes sur les sites et applications web ;  
> . permet de détecter une injection de base de données (injections SQL PHP/ASP/JSP et injections XPath)  
> . permet de détecter le Cross Site Scripting (XSS) réfléchi et permanent  
> . permet de détecter la divulgation de fichiers (inclusion locale et distante, require, fopen, readfile…)  
> . permet de détecter une exécution de commande (eval(), system(), passtru()…)
Injection XXE (Xml eXternal Entity)  
> . permet de détecter une injection CRLF
> . permet de détecter des fichiers potentiellement dangereux sur le serveur  
> . permet de détecter de contourner des configurations htaccess faibles  
> . permet de détecter des copies (sauvegarde) de scripts sur le serveur  
> . permet de détecter un Shellshock  
> . permet de détecter un DirBuster  
> . permet de détecter une contrefaçon de demande côté serveur (grâce à l'utilisation d'un site Web Wapiti externe)  
> . attention, il ne prend pas en charge l’exploitation des failles remontées  
> . génère des rapports de vulnérabilités dans différents formats (HTML, texte, JSON, XML)  

- __whatweb__

> . analyseur de site web qui fournit de nombreuses informations sur un site Web ;  
> . reconnaissance des technologies Web, y compris les systèmes de gestion de contenu (CMS)  
> . reconnaissance des plateformes de blogs  
> . reconnaissance des packages statistiques/analytiques  
> . reconnaissance des bibliothèques JavaScript  
> . reconnaissance des serveurs Web et des appareils intégrés  
> . peut identifier les versions, les adresses e-mail, les identifiants de compte, les modules de framework Web, les erreurs SQL, etc.  
> . dispose de plus de 1800 plugins  
> . peut être furtif et rapide, ou approfondi mais lent  

- __wpscan__

> . scanner de sécurité WordPress  
> . peut vérifier la version de WordPress installée et les éventuelles vulnérabilités associées  
> . peut vérifier quels plugins sont installés et toutes les vulnérabilités associées  
> . peut vérifier quels thèmes sont installés et toutes les vulnérabilités associées  
> . énumération du nom d'utilisateur  
> . peut identifier les utilisateurs avec des mots de passe faibles par brute-force  
> . peut vérifier les fichiers wp-config.php sauvegardés et accessibles au public  
> . peut vérifier les Vidages de base de données qui peuvent être accessibles au public  
> . peut vérifier si les journaux d'erreurs sont exposés par les plugins  
> . énumération des fichiers multimédias  
> . peut vérifier les fichiers Timthumb vulnérables  
> . peut vérifier si le fichier Lisez-moi de WordPress est présent  
> . peut vérifier si WP-Cron est activé  
> . peut vérifier si l'enregistrement de l'utilisateur est activé  
> . divulgation du chemin complet  
> . peut télécharger la liste des répertoires  

## L'IDENTIFICATION DE CMS

- __wpscan__

> . scanner de sécurité WordPress  
> . peut vérifier la version de WordPress installée et les éventuelles vulnérabilités associées  
> . peut vérifier quels plugins sont installés et toutes les vulnérabilités associées  
> . peut vérifier quels thèmes sont installés et toutes les vulnérabilités associées  
> . énumération du nom d'utilisateur  
> . peut identifier les utilisateurs avec des mots de passe faibles par brute-force  
> . peut vérifier les fichiers wp-config.php sauvegardés et accessibles au public  
> . peut vérifier les Vidages de base de données qui peuvent être accessibles au public  
> . peut vérifier si les journaux d'erreurs sont exposés par les plugins  
> . énumération des fichiers multimédias  
> . peut vérifier les fichiers Timthumb vulnérables  
> . peut vérifier si le fichier Lisez-moi de WordPress est présent  
> . peut vérifier si WP-Cron est activé  
> . peut vérifier si l'enregistrement de l'utilisateur est activé  
> . divulgation du chemin complet  
> . peut télécharger la liste des répertoires  

## PROCURATIONS DES WEBAPP

- __burpsuite__

> . appelé `burp`, c'est une suite d'outils d'audit de sécurité pour les plateformes, les sites et applications web  
> . permet d'accéder aux échanges entre le navigateur et le serveur web afin de comprendre l'architecture de la solution à auditer  
> . facilement configurable et modulaire, ses principales fonctions sont un proxy web et un scanner de vulnérabilité web ;  
> . le module proxy HTTP est un proxy d'interception pour se placer entre l'utilisateur et les applications HTTP  
> . le scanner de vulnérabilité lui permet l'automatisation de certains tests  
> . le module intruder permet de simuler ou de réaliser des attaques brute force  
> . le module repeater HTTP est un outil complémentaire du proxy HTTP pour modifier puis renvoyer les requêtes bloquées  

## ROBOTS D'INDEXATION

- __cutycapt__

> . outil CLI multiplateforme pour capturer le rendu WebKit d'une page web  
> . peut éditer aux formats matriciels et vectoriels, dont SVG, PDF, PS, PNG, JPEG, TIFF, GIF et BMP  

- __dirb__

> . scanner de contenu web qui cherche les objets web existants et/ou cachés  
> . peut parfois être utilisé comme un scanner CGI classique  
> . permet de contourner certaines restrictions du .htaccess  
> . attention, il ne recherche pas les vulnérabilités, c'est un scanner de contenu et non de vulnérabilité  

- __dirbuster__

> . outil de découverte des répertoires et fichiers cachés sur un serveur web  
> . fork du projet du même nom et repris par le groupe OWASP, il comprend deux modes : attaque par dictionnaire et par brute-force  
> . est fournis avec des listes de répertoires, fichiers et utilisateurs  
> . possibilité de modifier ces listes, d’y rajouter ces propres répertoires, fichiers ou utilisateurs  
> . supporte les protocoles HTTP et HTTPS  

- __ffuf__

> . scanner de répertoires et de fichiers pour application web par fuzzing  
> . permet la découverte de répertoires typiques, d'hôtes virtuels (sans enregistrements DNS) et le fuzzing des paramètres GET et POST  
> . peut aussi lire des jeux de données depuis l'entrée standard (STDIN) ou bien utiliser le générateur externe `Radamsa`  

- __wfuzz__

> . outil complètement modulaire conçu pour le bruteforcing d'applications Web  
> . peut être utilisé pour trouver des ressources non liées à des répertoires, `servlets`, scripts, etc.  
> . peut bruteforcer les paramètres GET et POST pour vérifier différents types d'injections (SQL, XSS, LDAP, etc),  
> . peut bruteforcer les paramètres des formulaires (utilisateur/mot de passe), Fuzzing, etc.  
> . permet d'injecter n'importe quelle entrée dans n'importe quel champ d'une requête HTTP  

## ___/___

- __commix__

> . outil complètement modulaire qui automatise la détection et l'exploitation de vulnérabilités par injection de commande  

- __sqlmap__

> . outil de test de pénétration qui automatise le processus de détection et d'exploitation des failles d'injection SQL  
> . comprend un puissant moteur de détection, de nombreuses fonctionnalités uniques pour l'auditeur et une large gamme d'options  

- __burpsuite__

> . appelé `burp`, c'est une suite d'outils d'audit de sécurité pour les plateformes, les sites et applications web  
> . permet d'accéder aux échanges entre le navigateur et le serveur web afin de comprendre l'architecture de la solution à auditer  
> . facilement configurable et modulaire, ses principales fonctions sont un proxy web et un scanner de vulnérabilité web ;  
> . le module proxy HTTP est un proxy d'interception pour se placer entre l'utilisateur et les applications HTTP  
> . le scanner de vulnérabilité lui permet l'automatisation de certains tests  
> . le module intruder permet de simuler ou de réaliser des attaques brute force  
> . le module repeater HTTP est un outil complémentaire du proxy HTTP pour modifier puis renvoyer les requêtes bloquées  

- __skipfish__

> . outil actif de reconnaissance de la sécurité des applications Web  
> . prépare un sitemap interactif du site ciblé en réalisant une analyse récursive et des sondes basées sur un dictionnaire  
> . très rapide en termes de requêtes tout en évitant d’utiliser trop le processeur  
> . outil de renseignement open source  
> . utilisé pour analyser les sites Web et les applications Web  
> . utilisé pour analyser les systèmes de gestion de contenu (CMS)  
> . peut trouver des vulnérabilités dans CMS  
> . dispose d'un grand nombre de modules  

- __wpscan__

> . scanner de sécurité WordPress  
> . peut vérifier la version de WordPress installée et les éventuelles vulnérabilités associées  
> . peut vérifier quels plugins sont installés et toutes les vulnérabilités associées  
> . peut vérifier quels thèmes sont installés et toutes les vulnérabilités associées  
> . énumération du nom d'utilisateur  
> . peut identifier les utilisateurs avec des mots de passe faibles par brute-force  
> . peut vérifier les fichiers wp-config.php sauvegardés et accessibles au public  
> . peut vérifier les Vidages de base de données qui peuvent être accessibles au public  
> . peut vérifier si les journaux d'erreurs sont exposés par les plugins  
> . énumération des fichiers multimédias  
> . peut vérifier les fichiers Timthumb vulnérables  
> . peut vérifier si le fichier Lisez-moi de WordPress est présent  
> . peut vérifier si WP-Cron est activé  
> . peut vérifier si l'enregistrement de l'utilisateur est activé  
> . divulgation du chemin complet  
> . peut télécharger la liste des répertoires  

# 04 - L'EVALUATION DATABASE

- __SQlite database browser__

> . outil pour créer, concevoir et modifier des fichiers de base de données compatibles avec SQLite ;  
> . l'utilisateur peut créer et compacter des fichiers de base de données  
> . l'utilisateur peut créer, définir, modifier et supprimer des tables  
> . l'utilisateur peut créer, définir et supprimer des index  
> . l'utilisateur peut parcourir, modifier, ajouter et supprimer des enregistrements  
> . l'utilisateur peut rechercher des enregistrements  
> . l'utilisateur peut importer et exporter des enregistrements sous forme de texte  
> . l'utilisateur peut importer et exporter des tableaux depuis/vers des fichiers CSV  
> . l'utilisateur peut importer et exporter des bases de données depuis/vers des fichiers de vidage SQL  
> . l'utilisateur peut émettre des requêtes SQL et inspecter les résultats  
> . l'utilisateur peut examiner un journal de toutes les commandes SQL émises par l'application  
> . l'utilisateur peut tracer des graphiques simples basés sur des données de table ou de requête  

- __sqlmap__

> . outil de test de pénétration qui automatise le processus de détection et d'exploitation des failles d'injection SQL  
> . comprend un puissant moteur de détection, de nombreuses fonctionnalités uniques pour l'auditeur et une large gamme d'options  

# 05 - ATTAQUE DE MOT DE PASSE

## ATTAQUE HORS CONNEXION

- __chntpw__

> . permet de supprimer ou réinitialiser le mot de passe Windows XP/Vista/Seven d'un compte local  
> . peut aussi changer les droits d’administrations ou bloquer des comptes locaux  
> . modifie le fichier de registre SAM, il n'est donc pas nécessaire de connaître le mot de passe antérieur ou d'être administrateur  
> . peut être exécuté à partir d'un CD ou d'une clé USB bootable  

- __hashcat__

> . l'outil de récupération de mot de passe le plus rapide et le plus avancé  
> . multi-OS (Linux, Windows et macOS)  
> . multi-plateforme (CPU, GPU, APU, etc., tout ce qui vient avec un runtime OpenCL)  
> . multi-Hash (craquage de plusieurs hachages en même temps)  
> . multi-Devices (Utilisation de plusieurs appareils dans le même système)  
> . types de périphériques multiples (utilisant des types de périphériques mixtes dans le même système)  
> . prend en charge la fonctionnalité de cerveau candidat au mot de passe  
> . Prise en charge des réseaux de craquage distribués (à l'aide de la superposition)  
> . prise en charge de la pause et de la reprise interactives  
> . prise en charge des sessions  
> . prise en charge de la restauration  
> . prise en charge de la lecture des candidats au mot de passe à partir d'un fichier et de `stdin`  
> . prise en charge du sel et du jeu de caractères hexadécimaux  
> . prise en charge de l'optimisation automatique des performances  
> . prise en charge de l'ordonnancement automatique des chaînes de Markov dans l'espace-clé
Système d'analyse comparative intégré  
> . chien de garde thermique intégré  
> . prend en charge cinq modes d'attaque uniques pour plus de 300 algorithmes de hachage hautement optimisés  
> . le seul moteur de règles intégré au noyau  

- __hashid__

> . outil pour identifier les différents types de hachages utilisés pour chiffrer les données et notamment les mots de passe  
> . prend en charge l'identification de plus de 220 types de hachage uniques à l'aide d'expressions régulières  
> . peut identifier un seul hachage, analyser un fichier, lire plusieurs fichiers et identifier les hachages qu'ils contiennent  
> . peut inclure le mode `hashcat` correspondant et/ou le format `JohnTheRipper` dans sa sortie  
> . attention, remplace `hash-identifier` qui est obsolète  

- __hash-identifier__

> . outil pour identifier les différents types de hachages utilisés pour chiffrer les données et notamment les mots de passe  
> . remplacé par `hashid`  

- __ophcrack-cli__

> . craqueur de mot de passe Windows stockés en LM hash et depuis la version 2.3 en NT hash  
> . variante du compromis original de Hellman, il fonctionne sur un compromis temps-mémoire utilisant des tables arc-en-ciel  
> . récupère 99,9% des mots de passe alphanumériques en quelques secondes  
> . ne prends pas en charge les mots de passe contenant des caractères spéciaux dans la version gratuite  
> . fonctionne pour Windows NT/2000/XP/Vista  

- __samdump2__

> . outil conçu pour vider les hachages de mot de passe Windows 2k/NT/XP/VISTA à partir d'un fichier SAM  
> . comprend `bkhive` qui récupère la clé de démarrage syskey à partir d'une ruche système Windows NT/2K/XP/VISTA  

## ATTAQUE EN LIGNE

- __hydra & hydra-graphical__

> . logiciel performant qui permet le brute force de mot passe dans plusieurs catégories telles que le web, ftp, ssh2, imap, etc.  
> . piratage de connexion parallélisé qui prend en charge de nombreux protocoles d’attaque  
> . outil très rapide et flexible qui peut être étendu grâce à des modules supplémentaires  
> . compilable sur Linux, Windows/Cygwin, Solaris, FreeBSD/OpenBSD, QNX (Blackberry 10) et MacOS  

- __patator__

> . outil de bruteforce polyvalent, avec une conception modulaire et une utilisation flexible  
> . peut bruteforcer du SSH, SMTP, MySQL, VNC, fichiers zip et les DNS (pour débusquer certains sous-domaines inconnus), etc.  
> . prend en charge de nombreux modules  
> . outil non compatible avec les scripts  
> . pas de faux négatifs : l'utilisateur décide des résultats à ignorer  
> . peut utiliser des connexions persistantes (tester plusieurs mots de passe jusqu'à ce que le serveur se déconnecte)  
> . Multi-thread  
> . tout paramètre de module peut être fuzzé  
> . peut enregistrer chaque réponse (ainsi que la demande) dans des fichiers journaux séparés pour un examen ultérieur  

- __thc-pptp-bruter__

> . outil entièrement autonome de bruteforce contre les points de terminaison pptp vpn (port tcp 1723)  
> . ne prend actuellement en charge que l'authentification Microsoft Windows ChapV2  
> . testé sur les passerelles Windows et Cisco  
> . exploite une faiblesse de l'implémentation anti-brute force de Microsoft  
> . permet d'essayer 300 mots de passe à la seconde sur un LAN et 5 à 50 mots de passe/seconde sur les réseaux distants  

- __onesixtyone__

> . scanner SNMP simple et rapide  
> . envoie des requêtes SNMP pour la valeur sysDescr de manière asynchrone  pour donner la description du logiciel exécuté  
> . heure d'envoi des requêtes réglagle par l'utilisateur  
> . balayage de tout un réseau de classe B en moins de 13 minutes  
> . peut être utilisé pour découvrir des périphériques répondant à des noms de communauté bien connus  
> . peut être pour monter une attaque par dictionnaire contre un ou plusieurs périphériques SNMP  

## PASSING THE HASH TOOLS

- __mimikatz__

> . outil offensif très efficace d'extraction d'identifiants et de mots de passe  
> . peut extraire les mots de passe en clair, le hachage, le code PIN et les tickets Kerberos de la mémoire  
> . peut également effectuer le pass-the-hash, le pass-the-ticket ou créer des Golden tickets  
> . inclut un module qui décharge le démineur de la mémoire de Windows et indique où se trouvent les mines dispersées  

- __pth__

> . le package `pass-the-hash` contient des versions modifiées de Curl, Iceweasel, FreeTDS, Samba 4, WinEXE et WMI  

- __smbmap__

> . énumérateur des lecteurs de partages Samba sur l'ensemble d'un domaine  

## PASSWORD PROFILING & WORDLIST

- __cewl__

> . générateur de liste de mots personnalisés en analysant une URL à pofondeur spécifiée  
> . peut lister des mots, des adresses mail et des noms d'utilisateur  

- __crunch__

> . générateur de liste de mots utilisé pour générer des mots clés personnalisés  
> . permet à l'utilisateur de spécifier un jeu de caractères défini ou standard  

- __rsmangler__

> . outil pour manipuler une liste de mot ou un fichier de dictionnaire  
> . peut générer des mots en imitant les tendances courantes de création humaines (utilise le langage l33t)  

- __wordlists__

> . fichiers dictionnaires : en l'occurrence le paquet de liste de mot rockyou.txt  

## ____/____

- __john__

> . JtR (John the Ripper) est un outil de craquage de mots de passe  
> . détecte automatiquement le mode de chiffrement des données hachées et les compares pour trouver des correspondances  
> . prend en charge une large gamme de cryptage et de formats  

- __medusa__

> . forceur de connexion rapide, parallèle et modulaire  
> . l'objectif est de prendre en charge autant de services qui permettent l'authentification à distance que possible  
> . les tests de force brute peuvent être effectués simultanément sur plusieurs hôtes, utilisateurs ou mots de passe  
> . les informations cibles (hôte/utilisateur/mot de passe) peuvent être spécifiées de différentes manières  
> . plusieurs protocoles et services pris en charge (par exemple, SMB, HTTP, POP3, MS-SQL, SSHv2, entre autres)  
> . chaque module de service existe sous la forme d'un fichier .mod indépendant  

- __ncrack__

> . outil de craquage d'authentification réseau à haut débit conçu pour identifier les mots de passe faibles  
> . conçu en utilisant une approche modulaire, une syntaxe de ligne de commande similaire à `Nmap` et un moteur dynamique  
> . permet un audit à grande échelle rapide mais fiable de plusieurs hôtes  
> . les protocoles pris en charge incluent RDP, SSH, http(s), SMB, pop3(s), VNC, FTP et telnet  

- __cewl__

> . générateur de liste de mots personnalisés en analysant une URL à pofondeur spécifiée  
> . peut lister des mots, des adresses mail et des noms d'utilisateur  

- __crunch__

> . générateur de liste de mots utilisé pour générer des mots clés personnalisés  
> . permet de spécifier un jeu de caractères défini ou standard  

- __wordlists__

> . fichiers dictionnaires : en l'occurence le paquet de liste de mot rockyou.txt  

- __hashcat__

> . l'outil de récupération de mot de passe le plus rapide et le plus avancé  
> . multi-OS (Linux, Windows et macOS)  
> . multi-plateforme (CPU, GPU, APU, etc., tout ce qui vient avec un runtime OpenCL)  
> . multi-Hash (craquage de plusieurs hachages en même temps)  
> . multi-Devices (Utilisation de plusieurs appareils dans le même système)  
> . types de périphériques multiples (utilisant des types de périphériques mixtes dans le même système)  
> . prend en charge la fonctionnalité de cerveau candidat au mot de passe  
> . Prise en charge des réseaux de craquage distribués (à l'aide de la superposition)  
> . prise en charge de la pause et de la reprise interactives  
> . prise en charge des sessions  
> . prise en charge de la restauration  
> . prise en charge de la lecture des candidats au mot de passe à partir d'un fichier et de `stdin`  
> . prise en charge du sel et du jeu de caractères hexadécimaux  
> . prise en charge de l'optimisation automatique des performances  
> . prise en charge de l'ordonnancement automatique des chaînes de Markov dans l'espace-clé
Système d'analyse comparative intégré  
> . chien de garde thermique intégré  
> . prend en charge cinq modes d'attaque uniques pour plus de 300 algorithmes de hachage hautement optimisés  
> . le seul moteur de règles intégré au noyau  

- __ophcrack-cli__

> . craqueur de mot de passe Windows stockés en LM hash et depuis la version 2.3 en NT hash  
> . variante du compromis original de Hellman, il fonctionne sur un compromis temps-mémoire utilisant des tables arc-en-ciel  
> . récupère 99,9% des mots de passe alphanumériques en quelques secondes  
> . ne prends pas en charge les mots de passe contenant des caractères spéciaux dans la version gratuite  
> . fonctionne pour Windows NT/2000/XP/Vista  

# 06 - ATTAQUE SANS FIL

## OUTILS BLUETOOTH

- __spooftooph__

> . conçu pour automatiser l'usurpation ou le clonage des informations d'un périphérique Bluetooth  
> . permet aux utilisateurs d'usurper leur adresse MAC, de cloner des paquets et d'effectuer d'autres attaques  
> . permet de dissimuler un périphérique Bluetooth dans un site ordinaire, d'accéder à des informations protégées et d'observer  

## OUTILS WIRELESS

- __bully__  

> . outil d'attaque par bruteforce WPS  
> . exploite le défaut de conception de la spécification WPS  
> . fonctionne sous Linux et spécifiquement développé pour des systèmes Linux embarqués  

- __fern wifi cracker (root)__

> . outil d'audit et d'attaque de sécurité sans fil  
> . capable de cracker et de récupérer des clés WEP/WPA/WPS  
> . capable d'exécuter d'autres attaques basées sur des réseaux sans fil ou Ethernet  
> . repose sur les outils `Aircrak-ng` et `Reaper` pour tenter de casser la protection du réseau  

## _____/_____

- __kismet__

> . détecteur de réseau et d'appareils sans fil, un renifleur, un outil de surveillance et un framework WIDS  
> . fonctionne avec des interfaces Wi-Fi, Bluetooth, certains matériels SDR et d'autres matériels de capture spécialisés  
> . sans envoyer lui-même de paquet décelable, il peut détecter des points d'accès et des clients sans fil et les associer  
> . inclut des fonctionnalités de détection de sniffeurs actifs de réseaux sans fils, comme `NetStumbler`  
> . peut journaliser les paquets sniffés et les sauvegarder dans des fichiers compatibles avec `tcpdump`, `Wireshark` ou `Airsnort`  
> . fonctionne sous Linux et MacOS  

- __pixiewps__

> . outil utilisé pour forcer hors ligne la méthode WPS PIN en exploitant la "pixie-dust attack"  
> . permet d'obtenir le code PIN en quelques secondes ou minutes seulement, en fonction de la vulnérabilité de la cible  

- __reaver__

> . outil qui permet de bruteforcer le PIN des point d'accès où le WPS est activé our récupérer les mots de passe WPA/WPA2  
> . peut forcer la méthode WPS PIN en exploitant la "pixie-dust attack"  
> . peut récupérer le WPA PSK et alternativement les paramètres sans fil du point d'accès peuvent être reconfigurés  

- __wifite__

> . outil pour auditer les réseaux sans fil cryptés WEP ou WPA  
> . utilise les outils `aircrack-ng`, `pyrit`, `reaver`, `tshark`  
> . peut être automatisable et s'exécuter sans supervision  
> . peut trier les réseaux wifi par puissance (en dB)  
> . peut sauvegarder tous les handshake WPA  
> . peut filtrer les réseaux  
> . la durée des timeout et le nombre de packets balancés à la seconde sont aussi paramétrables  
> . peut aussi détecter les cartes réseaux qui sont en mode monitor  
> . sauvegarde tous les mots de passe trouvés dans un log.txt  

- __fern wifi cracker (root)__

> . outil d'audit et d'attaque de sécurité sans fil  
> . capable de cracker et de récupérer des clés WEP/WPA/WPS  
> . capable d'exécuter d'autres attaques basées sur des réseaux sans fil ou Ethernet  
> . repose sur les outils `Aircrak-ng` et `Reaver` pour tenter de casser la protection du réseau  

# 07 - L'INGENIERIE INVERSE

- __clang & clang++__

> . compilateur pour les langages de programmation C, C++ et Objective-C dans le but d'offrir une aletrnative à GCC  
> . interface de bas niveau qui utilise les bibliothèques LLVM pour la compilation  
> . implémente toutes les normes ISO C++ 1998, 11 et 14 et fournit également la majeure partie du support de C++17  
> . depuis Xcode 4.2, Clang est le compilateur par défaut pour MacOS X  

- __nasm shell__

> . Netwide Assembler est un assembleur pour l'architecture x86, utilisant la syntaxe Intel (en)  
> . peut être utilisé pour produire à la fois des programmes 16 bits et 32 bits (IA-32)  
> . depuis la version 2 de NASM il est possible de produire des programmes 64 bits (x64)  
> . produit des fichiers binaires de forme plate, fichiers objets a.out, COFF, ELF Unix et Microsoft 16bits DOS et Win32  

- __radare2__

> . framework pour l'ingénierie inverse et l'analyse binaire qui implémente une interface de ligne de commande riche  
> . r2 permet d'analyser, émuler, déboguer, modifier et désassembler n'importe quel binaire  
> . composé d'un ensemble d'utilitaires pouvant être utilisés ensemble à partir du shell r2 ou indépendamment  

# 08 - OUTILS EXPLOITATION

- __crackmapexec (CME)__

> . outil couteau suisse pour tester les environnements Windows/Active Directory  
> . permet d'obtenir des informations sur des partages réseaux  
> . permet d'exécuter des commandes basiques sur des serveurs  
> . permet de faire du mass `mimikatz`  
> . permet de faire du mass `meterpreter` en combinaison avec `Empire` ou `metasploit`  
> . bypass d’Applocker  
> . permet de dumper les hashs locaux  
> . permet de stocker les informations dans une base de données  

- __metasploit framework__

> . outil incroyablement puissant pour exploiter les vulnérabilités de sécurité des systèmes informatiques  
> . plateforme qui prend en charge la recherche de vulnérabilités, le développement d'exploits et la création d'outils de sécurité  
> . le framework est modulaire, facilement extensible et il est soutenu par une communauté active  
> . permet de scanner et collecter des informations sur une machine cible  
> . permet de détecter et exploiter les vulnérabilités  
> . permet d'augmenter les privilèges d'un système d'exploitation  
> . permet d'installer une porte dérobée pour maintenir un accès persistant  
> . permet d'utiliser la technique de "Fuzzing" pour tester la robustesse d'un logiciel  
> . permet d'utiliser des outils d'évasion pour contourner les logiciels de sécurité  
> . permet d'utiliser des payloads pour exécuter des commandes à distance sur les systèmes compromis  
> . permet d'utiliser des outils de pivot pour propager l'accès à d'autres systèmes connectés  
> . permet d'effacer les traces et les journaux pour dissimuler les activités malveillantes  

- __msf payload creator (MSFPC)__

> . générateur rapide de charges utiles `Meterpreter` de base à l'aide de `msfvenom` qui fait partie du framework `Metasploit`  
> . peut générer plusieurs types de charges utiles : .apk, .asp, .aspx, .sh, .jsp, .elf, .macho, .pl, .php, .ps1, .py, .war et .exe/.dll  
> . permet de créer un exécutable correctement formaté pour fournir un shellcode à un système cible sans utiliser d'exploit  

- __searchsploit__

> . outil qui permet d'effectuer des recherches détaillées dans la base de données exploit-db  
> . permet d'effectuer des audits hors ligne  

- __social engineering toolkit (SET)__

> . outils destinés aux tests d'intrusion autour de l'ingénierie sociale  
> . multiplateforme et propose un choix de fonctions permettant diverses attaques basées sur l'hameçonnage informatique  
> . comprend l'outil `pêle-mêle`, un outil de mail-bombing , mais aussi le framework `Metasploit`1/2  

- __sqlmap__

> . outil de test de pénétration qui automatise le processus de détection et d'exploitation des failles d'injection SQL  
> . comprend un puissant moteur de détection, de nombreuses fonctionnalités uniques pour l'auditeur et une large gamme d'options  

# 09 - RENIFLER ET USURPATION

## RENIFLEURS DE RESEAU

- __dnschef__

> . un proxy DNS (alias "Fake DNS") utilisé pour l'analyse du trafic réseau des applications  
> . peut être utilisé pour simuler des requêtes pour que "badguy.com" pointe vers une machine locale  
> . hautement configurable et multiplateforme  

- __netsniff-ng__

> . renifleur de réseau Linux hautes performances pour l'inspection des paquets  
> . peut être utilisé pour l'analyse de protocole, la rétro-ingénierie ou le débogage de réseau  
> . mécanismes zero-copy et comprend les outils suivants :  
> . `netsniff-ng`, un analyseur de paquets sans copie, un outil de capture/relecture pcap  
> . `trafgen`, un générateur de paquets réseau multithread de bas niveau sans copie  
> . `mausezahn`, générateur de paquets de haut niveau pour les appliances avec Cisco-CLI  
> . `bpfc` un compilateur Berkeley Packet Filter, désassembleur Linux BPF JIT  
> . `ifpps` un outil de réseautage et de statistique système de type top  
> . `flowtop` un outil de suivi de connexion netfilter de type top  
> . `curvetun` un tunnel IP multi-utilisateur léger basé sur curve25519  
> . `astraceroute` un utilitaire de suivi de route de système autonome et de test DPI  

## USURPATION RESEAU

- __rebind__

> . outil qui implémente l'attaque de reliaison DNS à plusieurs enregistrements A  
> . peut être utilisé pour cibler n'importe quelle adresse IP publique (non RFC1918)  
> . fournit à un attaquant externe un accès à l'interface Web interne d'un routeur cible  
> . nécessite juste que l'utilisateur à l'intérieur du réseau cible navigue sur un site Web contrôlé ou compromis par l'attaquant  
> . fonctionne sur Linux, en root et iptables doit être installé et répertorié dans $PATH  

- __sslsplit__

> . outil pour les attaques man-in-the-middle contre les connexions réseau cryptées SSL/TLS  
> . peut intercepter et enregistrer le trafic basé sur SSL et ainsi écouter n'importe quelle connexion sécurisée  

- __tcpreplay__

> . suite d'outils pour éditer et rejouer le trafic réseau précédemment capturé  
> . permet de classer le trafic en tant que client ou serveur  
> . permet de réécrire les paquets des couches 2, 3 et 4  
> . permet de rejouer le trafic sur le réseau et via les commutateurs, routeurs, pare-feu, NIDS et IPS  
> . prend en charge les modes NIC simple et double pour tester à la fois les périphériques reniflants et en ligne  
> . permet de contrôler la vitesse à laquelle le trafic est rejoué et peut rejouer des traces `tcpdump` arbitraires  

- __dnschef__

> . un proxy DNS (alias "Fake DNS") utilisé pour l'analyse du trafic réseau des applications  
> . peut être utilisé pour simuler des requêtes pour que "badguy.com" pointe vers une machine locale  
> . hautement configurable et multiplateforme  

## ______/______

- __ettercap-graphical__

> . permet d'intercepter le trafic sur un segment réseau, capturer les mots de passe et réaliser des attaques Man In The Middle  
> . prend en charge la dissection active et passive de nombreux protocoles (même cryptés)  
> . inclut de nombreuses fonctionnalités pour l'analyse du réseau et de l'hôte  
> . l'injection de données et le filtrage à la volée sont possibles en maintenant la connexion synchronisée  
> . peut détecter un réseau local commuté et utiliser les empreintes digitales du système d'exploitation (actives ou passives)  

- __macchanger__

> . outil pour Linux qui permet de modifier les adresses MAC des interfaces réseau  

- __minicom__

> . outil de contrôle de modem et d'émulation de terminal de type Unix  
> . c'est un clone du programme de communication MS-DOS `Telix`  
> . il émule les terminaux ANSI et VT102  
> . il dispose d'un répertoire de numérotation et d'un téléchargement automatique zmodem  
> . il prend en charge des fichiers de verrouillage de style UUCP sur les périphériques série  
> . apporte un langage de script externe  

- __mitmproxy__

> . outil pour le débogage, les tests, les mesures de confidentialité et les tests de pénétration  
> . proxy interactif de type "man-in-the-middle" pour HTTP et HTTPS  
> . permet d'inspecter et de modifier les flux de trafic à la volée  
> . permet d'enregistrer les conversations HTTP pour une relecture et une analyse ultérieures  
> . permet de rejouer le côté client d'une conversation HTTP  
> . permet un mode reverse proxy  
> . mode proxy transparent sur OSX et Linux  
> . permet d'apporter des modifications scriptées au trafic HTTP à l'aide de Python  

- __responder__

> . il s'agit d'un poison LLMNR, NBT-NS et MDNS  
> . permet de rechercher un fichier d'hôtes local contenant des entrées DNS spécifiques  
> . permet d'effectuer automatiquement une requête DNS sur le réseau sélectionné  
> . permet d'utiliser LLMNR/NBT-NS pour envoyer des messages de diffusion au réseau sélectionné  
> . peut saisir le hachage du nom d'utilisateur et du mot de passe et les consigner  
> . peut avec certains services réseau demander aux utilisateurs des informations d'identification et les récupérer en clair  
> . peut effectuer des attaques de type pass-the-hash et fournir des shells distants  

- __wireshark__

> . outil de capture et analyse le trafic réseau  
> . disponible sur la plupart des systèmes d'exploitation  
> . capture le trafic du réseau local et stocke les données pour permettre leur analyse hors ligne  
> . capable de capturer le trafic Ethernet, Bluetooth, sans fil (IEEE.802.11), Token Ring, Frame Relay, etc.  
> . `TShark` est sa version CLI  

- __netsniff-ng__

> . renifleur de réseau Linux hautes performances pour l'inspection des paquets  
> . peut être utilisé pour l'analyse de protocole, la rétro-ingénierie ou le débogage de réseau  
> . mécanismes zero-copy et comprend les outils suivants :  
> . `netsniff-ng`, un analyseur de paquets sans copie, un outil de capture/relecture pcap  
> . `trafgen`, un générateur de paquets réseau multithread de bas niveau sans copie  
> . `mausezahn`, générateur de paquets de haut niveau pour les appliances avec Cisco-CLI  
> . `bpfc` un compilateur Berkeley Packet Filter, désassembleur Linux BPF JIT  
> . `ifpps` un outil de réseautage et de statistique système de type top  
> . `flowtop` un outil de suivi de connexion netfilter de type top  
> . `curvetun` un tunnel IP multi-utilisateur léger basé sur curve25519  
> . `astraceroute` un utilitaire de suivi de route de système autonome et de test DPI  

# 10 - MAINTIEN DE L'ACCES

## BACKDOORS OS

- __dbd__

> . clone de `Netcat` conçu pour être portable et offrir un cryptage fort  
> . fonctionne sur les systèmes d'exploitation de type Unix et sur Microsoft Win32  
> . propose le cryptage AES-CBC-128 + HMAC-SHA1, le choix du port source, la reconnexion continue avec délai, etc.  
> . prend uniquement en charge la communication TCP/IP  

- __powersploit__

> . une collection de modules Microsoft PowerShell qui peuvent aider le testeur d'intrusion  
> . permet de préparer et d'exécuter des scripts sur la machine cible  
> . permet d'ajouter des capacités de persistance à un script PowerShell  
> . permet d'extraire des données de la machine cible  
> . se compose d'un total de 8 modules et 36 scripts pour aider l'utilisateur  
> . permet de contourner l'antivirus et d'écouter le microphone de la machine cible  

- __sbd (Smart Development Bridge)__

> . outil qui communique avec un périphérique cible connecté  
> . gère plusieurs connexions avec les appareils cibles  
> . permet de répertorier les appareils connectés et d'envoyer une commande à un appareil spécifique  
> . fournit des commandes de base pour le développement d'applications, le transfert de fichiers, la commande shell distante  
> . permet la redirection de port pour un débogueur, l'affichage, le filtrage et le contrôle de la sortie du journal cible  
> . programme client-serveur composé d'un client, d'un démon et d'un serveur :

## BACKDOORS WEB

- __laudanum__

> . puissante collection de fichiers injectables conçus pour être utilisés dans un pentest  
> . fichiers écrits en plusieurs langues pour différents environnements  
> . l'objectif est de fournir un shell, des capacités de navigation dans les fichiers, des requêtes DNS, la récupération LDAP, etc.  
> .  cible les serveurs Web afin que les scripts soient écrits pour Cold Fusion, Classic ASP, ASP.Net, Java et PHP  
> . permet de limiter l'accès au fichier à des adresses IP spécifiques  

- __weevely__

> . un shell Web PHP furtif qui simule une connexion type telnet  
> . peut être utilisé comme porte dérobée furtive ou comme shell Web pour gérer des comptes Web légitimes  
> . permet un accès Shell à la cible  
> . console SQL pivotant sur la cible  
> . proxy HTTP/HTTPS pour parcourir la cible  
> . permet de charger et télécharger des fichiers  
> . permet de générer des shells TCP inverses et directs  
> . permet d'auditer la sécurité des cibles distantes  
> . permet le balayage des ports pivotant sur la cible  
> . monter le système de fichiers distant  
> . comptes brute force SQL pivotant sur la cible  

## TUNNEL

- __dns2tcpc & dns2tcpd__

> . outil pour relayer les connexions TCP sur DNS  
> . plusieurs connexions sont prises en charge  
> . l'encapsulation DNS doit être considérée comme une couche de transport non sécurisée et anonyme  

- __exe2hex__

> . outil de transfert de fichiers en ligne à l'aide des outils Windows intégrés `DEBUG.exe` ou `PowerShell`  
> . utile quand les administrateurs système ont bloqué le transfert, téléchargement, e-mail des fichiers EXE  

- __iodine__

> . outil qui permet de tunnelliser des données IPv4 via un serveur DNS  
> . utile dans des situations où l'accès à Internet est protégé par un pare-feu, mais où les requêtes DNS sont autorisées  
> . à besoin d'un appareil TUN/TAP pour fonctionner  
> . outil stable, facile à configurer et performant  
> . attention, ne crypte pas le trafic  
> . s'exécute sur diverses plates-formes, notamment Linux, Windows et macOS  

- __miredo__

> . outil de tunneling Teredo IPv6 pour Linux et les systèmes d'exploitation BSD  
> . destiné à fournir une connectivité IPv6 même derrière des périphériques NAT  
> . peut fournir une fonctionnalité de client Teredo ou de relais Teredo  

- __proxychains4__

> . outil UNIX qui permet de masquer notre IP en redirigeant le trafic réseau via une variété de proxys  
> . attention ne prend en charge que TCP  
> . agit comme un pilote sockscap / premeo / eborder (intercepte les appels TCP)  
> . la v4 prend en charge les serveurs proxy SOCKS4, SOCKS5 et HTTP CONNECT  
> . `proxychains-ng` est la suite du projet non maintenu `proxychains`, connu sous le nom de paquet proxychains dans Debian  

- __proxytunnel__

> . outil qui connecte stdin et stdout à un serveur d'origine quelque part sur Internet  
> . il relie un client à un serveur SSH sur le réseau au travers d'un proxy https ou http  
> . il est multiplateforme et permet de traverser un proxy HTTPS pour créer une connexion SSH  

- __ptunnel__

> . outil qui permet de faire passer une connexion TCP à travers le protocole ICMP (requêtes et réponses ping)  
> . permet une connexion fiable (les paquets perdus sont réémis)  
> . plusieurs connexions simultanées sont possibles  
> . prévoit une authentification pour éviter que n'importe qui utilise la connexion  
> . pratiques pour travailler dans un environnement réseau fermé avec des pare-feu et des proxys  

- __pwnat__

> . permet à plusieurs clients derrière des NAT de communiquer avec un serveur derrière un NAT séparé  
> . besoin de l'IP publique hébergeant le serveur, pas besoin de port forwarding et configuration DMZ et fonctionne en IPv6  
> . fonctionne avec les périphériques NAT de base (rfc 1631), ne fonctionnera pas avec une implémentation NAPT robuste  

- __sslh__

> . > . un multiplexeur ssl/ssh sur le port 443  
> . depuis la version 1.10 il supporte aussi le multiplexage de openvpn, tinc et xmpp (jabber)  
> . limité par les réseaux qui filtrent avec une liste blanche d'adresse IP  

- __stunnel4__

> . fonctionne comme un wrapper de cryptage SSL entre le client distant et le serveur local (inetd-startable) ou distant  
> . peut être utilisé pour ajouter des fonctionnalités SSL aux démons `inetd` sans aucune modification du code du programme  
> . transforme tout port TCP non sécurisé en un port crypté sécurisé en utilisant le package OpenSSL pour la cryptographie  
> . c'est en quelque sorte comme un petit VPN sécurisé qui s'exécute sur des ports spécifiques  

- __udptunnel__

> . outil qui permet de faire passer des paquets UDP de manière bidirectionnelle sur une connexion TCP  
> . autorise le trafic TCP/UDP/ICMP sur le tunneling UDP  
> . utile pour éviter les restrictions de pare feu  

- __dbd__

> . clone de `Netcat` conçu pour être portable et offrir un cryptage fort  
> . fonctionne sur les systèmes d'exploitation de type Unix et sur Microsoft Win32  
> . propose le cryptage AES-CBC-128 + HMAC-SHA1, le choix du port source, la reconnexion continue avec délai, etc.  
> . prend uniquement en charge la communication TCP/IP  

## _______/_______

- __evil-winrm__

> . outil qui contient le shell WinRM pour le piratage/pentesting  
> . utilise PSRP pour initialiser les pools d'espace d'exécution ainsi que pour créer et traiter des pipelines  
> . WinRM est un protocole basé sur SOAP, compatible avec les pare-feu et qui fonctionne avec HTTP (port 5985 par défaut)  
> . compatible avec les systèmes clients Linux et Windows  
> . peut charger en mémoire les scripts Powershell  
> . peut charger en mémoire les fichiers dll en contournant certains AV  
> . peut charger en mémoire les assemblages C# (C Sharp) en contournant certains AV  
> . peut charger des charges utiles x64 générées avec une technique de beignet impressionnante  
> . bypass AMSI dynamique pour éviter les signatures AV  
> . prise en charge du pass-the-hash  
> . prise en charge de l'authentification Kerberos  
> . prise en charge de SSL et des certificats  
> . peut charger et télécharger des fichiers affichant la barre de progression  
> . peut répertorier les services de la machine distante sans privilèges  
> . historique des commandes  
> . achèvement de la commande WinRM  
> . achèvement des fichiers/répertoires locaux  
> . achèvement du chemin distant : fichiers/répertoires (peut être désactivé en option)  
> . colorisation des messages d'invite et de sortie (peut être désactivée en option)  
> . fonctionnalité de journalisation facultative  
> . prise en charge de Docker (images prédéfinies disponibles sur Dockerhub)  
> . capture de piège pour éviter la sortie accidentelle du shell sur Ctrl + C  

- __exe2hex__

> . outil de transfert de fichiers en ligne à l'aide des outils Windows intégrés `DEBUG.exe` ou `PowerShell`  
> . utile quand les administrateurs système ont bloqué le transfert, téléchargement, e-mail des fichiers EXE  

- __impacket__

> . collection de classes Python3 pour travailler avec des protocoles réseau  
> . permet aux développeurs de créer et décoder des paquets réseau de manière simple et cohérente  
> . prend en charge des protocoles de bas niveau (IP, UDP et TCP) et des protocoles de niveau supérieur (NMB et SMB)  
> . très efficace lorsqu'il est utilisé en conjonction avec un utilitaire ou un package de capture de paquets tel que `Pcapy`  
> . les paquets peuvent être construits à partir de zéro et peuvent être analysés à partir de données brutes  

- __powersploit__

> . une collection de modules Microsoft PowerShell qui peuvent aider le testeur d'intrusion  
> . permet de préparer et d'exécuter des scripts sur la machine cible  
> . permet d'ajouter des capacités de persistance à un script PowerShell  
> . permet d'extraire des données de la machine cible  
> . se compose d'un total de 8 modules et 36 scripts pour aider l'utilisateur  
> . permet de contourner l'antivirus et d'écouter le microphone de la machine cible  

- __proxychains4__

> . outil UNIX qui permet de masquer notre IP en redirigeant le trafic réseau via une variété de proxys  
> . attention ne prend en charge que TCP  
> . agit comme un pilote sockscap / premeo / eborder (intercepte les appels TCP)  
> . la v4 prend en charge les serveurs proxy SOCKS4, SOCKS5 et HTTP CONNECT  
> . `proxychains-ng` est la suite du projet non maintenu `proxychains`, connu sous le nom de paquet proxychains dans Debian  

- __weevely__

> . un shell Web PHP furtif qui simule une connexion type telnet  
> . peut être utilisé comme porte dérobée furtive ou comme shell Web pour gérer des comptes Web légitimes  
> . permet un accès Shell à la cible  
> . console SQL pivotant sur la cible  
> . proxy HTTP/HTTPS pour parcourir la cible  
> . permet de charger et télécharger des fichiers  
> . permet de générer des shells TCP inverses et directs  
> . permet d'auditer la sécurité des cibles distantes  
> . permet le balayage des ports pivotant sur la cible  
> . monter le système de fichiers distant  
> . comptes brute force SQL pivotant sur la cible  

- __mimikatz__

> . outil offensif très efficace d'extraction d'identifiants et de mots de passe  
> . peut extraire les mots de passe en clair, le hachage, le code PIN et les tickets Kerberos de la mémoire  
> . peut également effectuer le pass-the-hash, le pass-the-ticket ou créer des Golden tickets  
> . inclut un module qui décharge le démineur de la mémoire de Windows et indique où se trouvent les mines dispersées  

# 11 - CRIMINALISTIQUE

## CRIMINALISTIQUE OUTILS A CISELER

- __magicrescue__

> . analyse un périphérique bloc pour les types de fichiers qu'il sait récupérer et appelle un programme externe pour les extraire  
> . peut être utilisé comme outil de restauration ou pour récupérer un lecteur ou une partition corrompue  
> . attention, outil qui n'est plus en développement actif  
> . attention avis de sécurité : ne doit être exécuté que dans un environnement type bac à sable (lire page GitHub)  
> . fonctionne sur n'importe quel système de fichiers  
> . ne peut récupérer que le premier morceau de chaque fichier sur des systèmes de fichiers très fragmentés  

- __scalpel__

> . outil de découpage et d'indexation de fichiers qui s'exécute sous Linux et Windows  
> . sculpteur de fichiers rapide qui lit une base de données de définitions d'en-tête et de pied de page et extrait les fichiers correspondants  
> . créé avec une amélioration de `Foremost` qui est un outil de récupération de données  

- __scrounge-ntfs__

> . outil de récupération de données pour les partitions NTFS  
> . il lit chaque bloc du disque dur et essaie de reconstruire l'arborescence du système de fichiers d'origine dans un répertoire  

## OUTILS D'INVESTIGATION D'IMAGERIE

- __guymager (root)__

> . outil qui fonctionne sous Linux pour l'acquisition de médias  
> . conçu pour prendre en charge différents formats de fichiers image, pour être convivial et pour fonctionner très rapidement  
> . Il est basé sur `libewf` et `libguytools`  
> . rapide : conception en pipeline multi-thread et à la compression des données multi-thread  
> . utilise pleinement les machines multiprocesseurs  
> . génère des images plates (dd), EWF (E01) et AFF, prend en charge le clonage de disque  

## OUTILS D'INVESTIGATION PDF

- __pdfid__

> . outil Python pour analyser et nettoyer les fichiers PDF  
> . permet d'identifier les documents PDF qui contiennent (par exemple) JavaScript ou d'exécuter une action lorsqu'ils sont ouverts  
> . analyse un document PDF et comptera les occurrences (totales et masquées) de chaque mot  

- __pdf-parser__

> . outil PHP autonome pour extraire des données à partir de fichiers PDF  
> . permet de charger/analyser des objets et des en-têtes  
> . permet d'extraire les métadonnées (auteur, description, ...)  
> . permet d'extraire le texte des pages commandées  
> . prend en charge des PDF compressés  
> . prend en charge de l'encodage du jeu de caractères romain MAC OS  
> . gestion de l'encodage hexa et octal dans les sections de texte  
> . permet de créer des configurations personnalisées  

## SUITES CRIMINALISTIQUE

- __autopsy (root)__

> . outil utilisé pour l'analyse des systèmes de fichiers Windows et UNIX (NTFS, FAT, FFS, EXT2FS et EXT3FS)  
> . peut aussi être utilisé pour récupérer des fichiers supprimés et afficher divers secteurs d'images téléchargées  
> . le navigateur `Autopsy` est une interface graphique pour les outils d'analyse CLI `The Sleuth Kit`  
> . `The Sleuth Kit` et `Autopsy` offrent des fonctionnalités proches à celles des outils de digital forensics commerciaux  

- __blkcalc__

> . convertit les points de disque non alloués en points de disque normaux  
> . peut prendre en charge de nombreux types de systèmes de fichiers  
> . si un système de fichiers n'est pas défini au départ peut trouver le type de système de fichiers  
> . autrefois appelé `dcalc`  

- __blkcat__

> . affiche le contenu de l'unité de données du système de fichiers dans une image disque  
> . autrefois appelé `dcat`  

- __blkls__

> . répertorie ou produit les unités de données du système de fichiers  
> . autrefois appelé `dls` dans TSK et `unrm`dans TCT  

- __blkstat__

> . Affiche les détails d'une unité de données du système de fichiers (c'est-à-dire un bloc ou un secteur)  
> . peut utiliser la commande `addr` qui affiche les statistiques d'un élément de données  
> . autrefois appelé `dstat`  

- __ffind__

> . trouve le nom du fichier ou du répertoire à l'aide d'un inode donné  
> . par défaut il ne renverra que le prénom qu'il trouve  
> . peut trouver des noms de fichiers supprimés  
> . peut trouver plusieurs noms de fichiers  

- __fls__

> . répertorie tous les noms de fichiers et répertoires dans un fichier image  
> . peut afficher les noms des fichiers qui ont été récemment supprimés  

- __fsstat__

> . affiche les détails généraux d'un système de fichiers  

- __hfind__

> . recherche une valeur de hachage dans une base de données de hachage  
> . permet de créer facilement une base de données de hachage et d'identifier si un fichier est connu ou non  
> . fonctionne avec la bibliothèque nationale de référence du logiciel NIST (NSRL) et renvoie `md5sum`

- __icat-sleuthkit__

> . affiche le contenu d'un fichier en fonction de son numéro d'inode

- __ifind__

> . trouve la structure de métadonnées qui a alloué une unité de disque ou un nom de fichier donné  
> . parfois l'une des structures peut être non allouée, mais cela trouvera toujours les résultats  

- __ils-sleuthkit__

> . liste les informations d'inode  
> . par défaut, il répertorie uniquement les inodes des fichiers supprimés  

- __img_cat__

> . affiche le contenu d'un fichier image  

- __img_stat__

> . affiche les détails associés à un fichier image  

- __istat__

> . affiche les détails d'une structure de métadonnées (c'est-à-dire inode)  

- __jcat__

> . affiche le contenu d'un bloc dans le journal du système de fichiers  

- __jls__

> . liste le contenu d'un journal de système de fichiers  

- __mactime-sleuthkit__

> . crée une chronologie ASCII de l'activité des fichiers basée sur la sortie de l'outil `fls`  
> . peut être utilisé pour détecter un comportement anormal et reconstruire des événements  
> . peut éventuellement utiliser une date de début ou une plage de dates pour limiter les données imprimées  
> . créé à l'origine pour analyser les systèmes Unix, certaines colonnes ont peu de sens lors de l'analyse d'un système Windows  

- __mmcat__

> . affiche le contenu d'un volume spécifique sur stdout  
> . permet d'extraire le contenu d'une partition dans un fichier séparé  

- __mmls__

> . affiche la disposition des partitions d'un système de volumes (tables de partitions)  
> . généralement utilisé pour répertorier le contenu de la table de partition afin de déterminer où commence chaque partition  
> . la sortie identifie le type de partition et sa longueur  

- __mmstat__

> . affiche les détails sur le système de volume (tables de partition)  

- __sigfind__

> . trouve une signature binaire dans un fichier  
> . peut être utilisé pour rechercher des secteurs de démarrage perdus, des superblocs et des tables de partition  
> . le format hexadécimal doit être utilisé pour trouver la signature binaire  

- __sorter__

> . fait un tri sur un système de fichiers pour l'organiser en fichiers alloués et non alloués, en fonction du type de fichier  
> . outil exécute une commande sur chaque fichier et trie les fichiers en fonction des fichiers de configuration  

- __srch_strings__

> . affiche les chaînes imprimables dans les fichiers  

- __tsk_comparedir__

> . outil qui compare le contenu de l'image au contenu du répertoire de comparaison  
> . très utile en phase de test pour identifier les rootkits  

- __tsk_gettimes__

> . outil qui collecte les heures MAC à partir d'une image disque spécifiée et convertit les heures en un fichier corps  
> . il examine chaque système de fichiers d'une partition ou d'une image de disque et traite les données à l'intérieur  
> . peut ensuite être utilisées comme entrée du système pour générer une chronologie de l'activité du fichier  
> . les données peuvent ensuite être imprimées sous forme de fichier  

- __tsk_loaddb__

> . charge les métadonnées de l'image disque dans une base de données SQLite  
> . la base de données est stockée dans le répertoire d'images pour un accès facile  
> . prend en charge de nombreux systèmes de fichiers et peut calculer la valeur de hachage MD5 pour chaque fichier  

- __tsk_recover__

> . outil qui transfert les fichiers d'une partition de disque vers un répertoire racine local  
> . les fichiers récupérés par défaut sont uniquement des fichiers non alloués, mais tous les fichiers peuvent être exportés  

## ________/________

- __autopsy (root)__

> . outil utilisé pour l'analyse des systèmes de fichiers Windows et UNIX (NTFS, FAT, FFS, EXT2FS et EXT3FS)  
> . peut aussi être utilisé pour récupérer des fichiers supprimés et afficher divers secteurs d'images téléchargées  
> . le navigateur `Autopsy` est une interface graphique pour les outils d'analyse CLI `The Sleuth Kit`  
> . `The Sleuth Kit` et `Autopsy` offrent des fonctionnalités proches à celles des outils de digital forensics commerciaux  

- __binwalk__

> . outil permettant de rechercher dans une image binaire des fichiers incorporés et du code exécutable  
> . en plus du micrologiciel il peut analyser des fichiers/images de système pour trouver de nombreux types de fichiers  
> . contient un grand nombre de signatures de divers fichiers grâce auxquelles le programme peut trouver des fichiers intégrés  
> . peut être utilisé pour identifier les types de fichiers sans extensions  
> . capable de calculer l'entropie des sections de fichiers et de construire un graphique d'entropie  
> . utilise la bibliothèque `libmagic` il est compatible avec les signatures magiques créées pour l’utilitaire de fichiers Unix  
> . attention, utilise de nombreux utilitaires d'extraction tiers qui peuvent avoir des problèmes de sécurité non corrigés  

- __bulk_extractor__

> . outil qui analyse une image disque, fichier ou répertoire de fichiers et extrait des informations utiles  
> . extrait des informations structurées (adresses mail, numéros de CB, etc.) sans analyser le système de fichiers  
> . les résultats sont stockés dans des fichiers qui peuvent être inspectés, analysés ou traités avec des outils automatisés  
> . crée des histogrammes des caractéristiques qu'il trouve  
> . peut trouver des éléments tels que des fichiers JPEG encodés en BASE64 et des objets JSON compressés  

- __hashdeep__

> . framework permettant de calculer de manière récursive des hachages avec plusieurs algorithmes simultanément  
> . peut comparer ces sommes de hachage avec une liste de hachages connus  
> . peut afficher ceux qui correspondent à la liste ou ceux qui ne correspondent pas  
> . peut afficher une estimation du temps lors du traitement de fichiers volumineux  
> . peut effectuer un hachage par morceaux (hacher les fichiers d'entrée dans des blocs de taille arbitraire)  

# 12 - RAPPORTS

- __cutycapt__

> . outil CLI multiplateforme pour capturer le rendu WebKit d'une page web  
> . peut éditer aux formats matriciels et vectoriels, dont SVG, PDF, PS, PNG, JPEG, TIFF, GIF et BMP  

- __faraday start__

> . un IDE de test de pénétration multi-utilisateur  
> . conçu pour distribuer, indexer et analyser les données générées lors d'un audit de sécurité  
> . agrège et normalise les données chargées pour les explorer dans des visualisations utiles aux gestionnaires et aux analystes  

- __pipal__

> . outil pour donner les statistiques et les informations afin d'aider à analyser les mots de passe  
> . peut être utile lors de l'analyse de volumineux vidages de mots de passe ou lors d'une activité de pentest  

- __recordmydesktop__

> . outil permettant d'effectuer des screencast (capturer l'image et le son) du bureau  
> . fournit une vidéo au format Ogg Théora  

- __maltego__

> . puissant outil d'investigation OSINT grâce à ses 30 patenaires  
> . mappage d'extraction de données de sources disparates  
> . analyse de liens sur jusqu'à 10.000 XNUMX entités sur un seul graphique  
> . possibilité de renvoyer jusqu'à 12 résultats par transformation  
> . inclusion de nœuds de collecte qui regroupent automatiquement les entités ayant des caractéristiques communes  
> . partagez des graphiques en temps réel avec plusieurs analystes en une seule session  
> . larges options d'exportation de graphiques  

# 13 - SOCIAL ENGINEERING TOOLS

- __msf payload creator (MSFPC)__

> . générateur rapide de charges utiles `Meterpreter` de base à l'aide de `msfvenom` qui fait partie du framework `Metasploit`  
> . peut générer plusieurs types de charges utiles : .apk, .asp, .aspx, .sh, .jsp, .elf, .macho, .pl, .php, .ps1, .py, .war et .exe/.dll  
> . permet de créer un exécutable correctement formaté pour fournir un shellcode à un système cible sans utiliser d'exploit  

- __social engineering toolkit (root)__

> . outils destinés aux tests d'intrusion autour de l'ingénierie sociale  
> . multiplateforme et propose un choix de fonctions permettant diverses attaques basées sur l'hameçonnage informatique  
> . comprend l'outil `pêle-mêle`, un outil de mail-bombing , mais aussi le framework `Metasploit`1/2  

- __maltego__

> . puissant outil d'investigation OSINT grâce à ses 30 patenaires  
> . mappage d'extraction de données de sources disparates  
> . analyse de liens sur jusqu'à 10.000 XNUMX entités sur un seul graphique  
> . possibilité de renvoyer jusqu'à 12 résultats par transformation  
> . inclusion de nœuds de collecte qui regroupent automatiquement les entités ayant des caractéristiques communes  
> . partagez des graphiques en temps réel avec plusieurs analystes en une seule session  
> . larges options d'exportation de graphiques  
