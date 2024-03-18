#!/bin/bash

# version 5
# ----------------------------------------------------------------------------------------------
# A faire : vérifier la crontab et le parfeu


monprogramme="Securisation d'un serveur LAMP"
#Avec SSH, Fail2ban, Clamav 			Logwatch, Portsentry, Fail2ban, Kippo, Securisation SSH (Clé de chiffrement/enregistrement SSHFP dans DNS, changement du port...), Clamav, RKhunter, Certificat SSL, | port-knocking, parefeu, DNS/dnssec
auteur="Logan Le Paire"


echo "Lancement du programme '$monprogramme'"
echo "Réalisé par $auteur"


#Variables modifables
mail="logan.lepaire@gmail.com" # Mail utilisé pour recevoir les alertes
domaine="loganlepaire" # Nom de domaine utilisé pour notre site
extension=".fr" # Extension de domaine utilisé pour notre site
ipserv=$(hostname -I | cut -f1 -d' ') # Adresse IP de notre serveur web (tester avec %IP%)
portSSH="63127" # Utiliser le port SSH par defaut (22) n'est pas recomandé. il faut choisir un port entre 1024 a 65535.
serveurname="srvwebdns" #Le nom de notre serveur

#Variables modifiés automatiquement (ne pas y toucher)
<<comment
path="$domaine"and".conf"
nomdusite="$domaine$extension"
ipinverse= $(echo $ipserv | awk -F. '{print $3"." $2"."$1}')
ipinversesrv= $(echo $ipserv | awk -F. '{print $4}')
comment

# Mise à jour du système    #faire crontab update
<<comment
echo ""
echo "Mise à jour du système..."
#export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -y && sudo apt-get upgrade -y
comment
sudo apt purge openssh-server clamav rkhunter postfix logwatch fail2ban -y
sudo apt autoremove -y


# Installation d'un serveur SSH 
<<comment
echo ""
echo "Installation de OpenSSH..."
sudo apt-get install -y openssh-server
systemctl start sshd

# Configuration de SSH
echo ""
echo "Configuration de SSH..."
sudo chown root:root /etc/ssh/ssh_host_*_key
chmod -R 600 /etc/ssh/ssh_host_*_key
sudo sed -i 's/.*Port.*/Port 63127/' /etc/ssh/sshd_config #Le serveur SSH doit dorénavant écouter sur le port 63127
sudo sed -i 's/.*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config #L’accès SSH par l’utilisateur root doit être interdite
sudo sed -i 's/.*Protocol.*/Protocol 2/' /etc/ssh/sshd_config #Utilisation de la version 2 du protocole SSH
sudo sed -i 's/.*StrictModes.*/StrictModes yes/' /etc/ssh/sshd_config # les droits sur les fichiers sont appliqués de manière stricte par SSH
sudo sed -i 's/.*UsePrivilegeSeparation.*/UsePrivilegeSeparation sandbox/' /etc/ssh/sshd_config #Mise en œuvre d'une séparation des privilèges à l’aide d’un bac à sable
sudo sed -i 's/.*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config #L’accès à distance par des comptes ne disposant pas de mot de passe doit être interdit
sudo sed -i 's/.*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config #Autoriser 3 tentatives de connexion successives en cas d’erreur dans le mot de passe
sudo sed -i 's/.*PrintLastLog.*/PrintLastLog yes/' /etc/ssh/sshd_config #Le service doit afficher les informations de dernière connexion à l’utilisateur quand il se connecte #ou "no" ???
#AllowTcpForwarding no
#MaxSessions 2
#TCPKeepAlive no
#X11Forwarding no
#AllowAgentForwarding no
#LogLevel VERBOSE
#LoginGraceTime 2m
#ClientAliveInterval  300
#ClientAliveCountMax 0
#PrintMotd no
#Banner none
#AllowUsers ...
echo "#disable weak ssh key exchange algorithms
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com
" >> /etc/ssh/sshd_config  # Empêche l’usage d’algorithmes de chiffrement dépréciés

#Mise en place d’une authentification SSH par clés de chiffrement
sed -i 's/.*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/.*AuthorizedKeysFile.*/AuthorizedKeysFile .ssh/authorized_keys/' /etc/ssh/sshd_config
sudo service ssh restart

echo ""
echo "Le client doit créer une paire de clés de chiffrement :"
echo "ssh-keygen -b 1024 -t ecdsa" # generation coté client d'une paire de clés ecdsa
echo "puis ajouter un 'passphrase'"
echo "Sur la machine cliente, pour la premiere connexion, nous pourrons nous connecter à notre serveur avec la commande suivante"
echo "ssh-copy-id -i <chemin/nomfichier><utilisateur>@<adresseIP ou nom> -p <numport>"
echo "Ce qui nous donne : ssh-copy-id -i ~/.ssh/id_ecdsa.pub logan@$ipserv -p $portSSH"
echo "Nous nous connectons ensuite avec : ssh logan@$ipserv -p $portSSH, apres cela il faut saisir le passphrase."
comment


# Installation de Fail2ban
<<comment
echo ""
echo "Installation de Fail2ban..."
sudo apt-get install fail2ban -y
sudo systemctl start fail2ban # (lance le service fail2ban)
sudo systemctl enable fail2ban # (active le démarrage automatique)

echo ""
echo "Configuration de Fail2ban..." #banissant une adresse IP au bout de 5 tentatives de connexions infructueuse"
touch /etc/fail2ban/jail.d/custom.conf
echo "[DEFAULT]
ignoreip = 127.0.0.1 $ipserv
findtime = 10m
bantime = 24h
maxretry = 5
destemail = $mail
action = %(action_mwl)s
[sshd]
enabled = true
port = $portSSH
logpath = /var/log/auth.log
[recidive]
enabled = true
logpath  = /var/log/fail2ban.log
banaction = %(banaction_allports)s
bantime  = 1w
findtime = 1d" > /etc/fail2ban/jail.d/custom.conf
sudo systemctl restart fail2ban
comment


# Clamav (antivirus) 
<<comment
echo "Installation de Clamav..."
apt-get install clamav clamav-daemon inotify-tools libnotify-bin -y
echo "#!/bin/sh
sudo systemctl stop clamav-freshclam.service
/usr/bin/freshclam -v >> /var/log/resul_freshclam.txt
sudo freshclam
systemctl start clamav-freshclam
clamscan" >> /etc/cron.daily/clamav
sudo chmod +x /etc/cron.daily/clamav
#sudo /etc/cron.daily/clamav 
#sudo dpkg-reconfigure clamav-freshclam  #Permet de configurer clamav
echo ""
#https://fr.wikipedia.org/wiki/Fichier_de_test_Eicar	Tester le faux positif eicar permet de savoir si l'antivirus fonctionne"
comment
#sudo clamscan --remove -r /home 
#sudo clamdscan --fdpass -i --move=/tmp
#sudo clamdscan --fdpass -i --move=/tmp -m 

echo "sudo clamscan --fdpass --remove -r /tmp" > /etc/cron.monthly/clamav
sudo chmod +x /etc/cron.monthly/clamav





#Non fonctionnel :



#sudo apt-get install debsums apt-listbugs needrestart apt-show-versions fail2ban unattended-upgrades clamav clamav-daemon rkhunter #https://www.it-connect.fr/scan-de-votre-systeme-unix-avec-lynis/
echo '#!/bin/bash
# Script "ClamAV Temps Réel", par HacKurx
# https://hackurx.wordpress.com
# Licence: GPL v3
# Dépendance: clamav-daemon inotify-tools
# Recommandé pour PC de bureau: libnotify-bin

DOSSIER=/home
QUARANTAINE=/tmp
LOG=$HOME/.clamav-tr.log

inotifywait -q -m -r -e create,modify,access "$DOSSIER" --format "%w%f|%e" | sed --unbuffered "s/|.*//g" |

while read FICHIER; do
    clamdscan --quiet --no-summary --fdpass -i -m "$FICHIER" --move=$QUARANTAINE
    if [ "$?" == "1" ]; then
		echo "`date` - Malware trouvé dans le fichier "$FICHIER". Le fichier a été déplacé dans $QUARANTAINE." >> $LOG 
		echo -e "\033[31mMalware trouvé!!!\033[00m Le fichier "$FICHIER" a été déplacé en quarantaine."
		if [ -f /usr/bin/notify-send ]; then
			notify-send -u critical "ClamAV Temps Réel" "Malware trouvé!!! Le fichier '$FICHIER' a été déplacé en quarantaine."
		fi
    fi
done
' > /etc/init.d/clamav-tr.sh
chmod +x /etc/init.d/clamav-tr.sh

#Postfix requis :

#Rkhunter (detecteur de rootkit)
<<comment
echo ""
echo "Installation de RKhunter..."
apt-get install rkhunter -y
echo "
REPORT_EMAIL="$mail"
CRON_DAILY_RUN="yes"
PKGMGR=DPKG
APT_AUTOGEN="yes"
" > /etc/default/rkhunter
echo "sudo rkhunter --update" >> /etc/cron.daily/rkhunter #ajoute les mises a jour journalières
comment

#Logwatch
<<comment
echo ""
Echo "Installation de Logwatch..."
sudo apt install logwatch -y
sed -i 's/.*MailTo.*/MailTo = logan.lepaire@gmail.com/' /usr/share/logwatch/default.conf/logwatch.conf
comment



# > = remplace
# >> = ajoute
