#!/bin/bash
# Script de Sécurisation SSH
# Par Logan Le Paire
# Version 6
---------------------------------------------------------------------------
# Variables
ipserv=$(hostname -I | cut -f1 -d' ') # Adresse IP de notre serveur
#mail=$(whiptail --inputbox "Pour recevoir des alertes par mail, saisissez une adresse e-mail" 8 39 exemple.test@gmail.com --title "Adresse mail" 3>&1 1>&2 2>&3)            # Mail utilisé pour recevoir les alertes
portSSH=$(whiptail --inputbox "Pour changer le port SSH, merci de choisir un port entre 1024 a 65535" 8 39 63127 --title "Port SSH (22 par défault)" 3>&1 1>&2 2>&3)        # Utiliser le port SSH par defaut (22) n'est pas recomandé. il faut choisir un port entre 1024 a 65535.



# Mise à jour du système
echo ""
echo "Mise à jour du système..."
sudo apt-get update -y && sudo apt-get upgrade -y

# Automatisation des mises à jour
echo "#!/bin/sh
sudo apt-get update -y && sudo apt-get upgrade -y" > /etc/cron.daily/update.sh
sudo chmod +x /etc/cron.daily/update.sh


# Installation d'un serveur SSH 
echo ""
echo "Installation de OpenSSH..."
sudo apt-get install -y openssh-server
systemctl start sshd

# Configuration de SSH
echo ""
echo "Configuration de SSH..."
sudo chown root:root /etc/ssh/ssh_host_*_key
chmod -R 600 /etc/ssh/ssh_host_*_key
sudo sed -i "s/.*Port.*/Port $portSSH/" /etc/ssh/sshd_config                                              #Le serveur SSH doit dorénavant écouter sur le port 63127
sudo sed -i 's/.*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config                           #L’accès SSH par l’utilisateur root doit être interdite
sudo sed -i 's/.*Protocol.*/Protocol 2/' /etc/ssh/sshd_config                                          #Utilisation de la version 2 du protocole SSH
sudo sed -i 's/.*StrictModes.*/StrictModes yes/' /etc/ssh/sshd_config                                  #Les droits sur les fichiers sont appliqués de manière stricte par SSH
sudo sed -i 's/.*UsePrivilegeSeparation.*/UsePrivilegeSeparation sandbox/' /etc/ssh/sshd_config        #Mise en œuvre d'une séparation des privilèges à l’aide d’un bac à sable
sudo sed -i 's/.*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config                 #L’accès à distance par des comptes ne disposant pas de mot de passe doit être interdit
sudo sed -i 's/.*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config                                  #Autoriser 3 tentatives de connexion successives en cas d’erreur dans le mot de passe
sudo sed -i 's/.*PrintLastLog.*/PrintLastLog yes/' /etc/ssh/sshd_config                                #Le service doit afficher les informations de dernière connexion à l’utilisateur quand il se connecte #ou "no" ???
sudo sed -i 's/.*AllowTcpForwarding.*/AllowTcpForwarding no/' /etc/ssh/sshd_config
sudo sed -i 's/.*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
sudo sed -i 's/.*MaxSessions.*/MaxSessions 2/' /etc/ssh/sshd_config
#TCPKeepAlive no
#AllowAgentForwarding no
#LogLevel VERBOSE
#LoginGraceTime 2m
#ClientAliveInterval  300
#ClientAliveCountMax 0
#PrintMotd no
#Banner none
#AllowUsers ...

#Désactivation de l’usage d’algorithmes de chiffrement dépréciés
echo "#Disable weak ssh key exchange algorithms
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com
" >> /etc/ssh/sshd_config  



#Mise en place d’une authentification SSH par clés de chiffrement
sed -i 's/.*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/.*AuthorizedKeysFile.*/AuthorizedKeysFile .ssh/authorized_keys/' /etc/ssh/sshd_config
sudo service ssh restart


whiptail --title "Authentification SSH par clés de chiffrement coté client" --msgbox "Génération de clé avec :
ssh-keygen -t rsa -b 2048

Ou bien :
ssh-keygen -t ecdsa -b 256

Il faudra ensuite ajouter un 'passphrase'.


Premiere connexion :
ssh-copy-id -i <chemin/nomfichier><utilisateur>@<IP ou nom> -p <port>

Ce qui nous donne : 
ssh-copy-id -i ~/.ssh/id_ecdsa.pub logan@$ipserv -p $portSSH

Lors de la première connexion le passephrase nous sera demandé, puis ce ne sera plus le cas.

Nous nous connectons ensuite avec : 
ssh utilisateur@$ipserv -p $portSSH
" 26 78 16 




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
#destemail = $mail
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
