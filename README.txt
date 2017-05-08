KSH: Kernel shell

KSH est un outil permettant d'intéragir avec le noyau via l'appel système
ioctl() afin de lui faire exécuter des commandes.

KSH est découpé en 2 parties:
	- un module pour kernel linux, appelé ksh
	- un outil en mode utilisateur permettant d'intéragir avec le module,
	  appelé ksh_tool

Il a été développé sous Linux version 4.2.3 patchée.

COMPILATION: 

Avant d'être compilé, le patch "swapinfo.patch" présent à la racine du projet doit être appliqué aux sources du noyau: à la racine des sources du kernel: "patch -p1 < swapinfo.patch".
Puis recompiler le kernel.

Le Makefile situé à la racine du projet permet de compiler à la fois le module et l'outil utilisateur.
Cependant, il est nécessaire de faire pointer la variable KERNELDIR du Makefile du répertoire module/ vers les sources du noyau linux afin que le module puisse être compilé.

INSTALLATION:

L'installation du module se fait en 3 étapes:
1) Ajout du module au noyau:
	$ insmod ksh.ko
2) Noter le numéro de majeur enregistré par le module:
	$ dmesg | tail -n 15
3) Créer le fichier device associé au module:
	$ mknod /dev/ksh c <num_major> 0

Tester en exécutant l'outil compilé dans bin/ksh_tool.

COMMANDES:

ksh_tool est un petit shell permettant d'éxécuter différentes commandes:

Une fois l'outil lancé un prompt apparait, il est alors possible de lister les commandes disponibles via la commande 'help' ou de quitter le prompt via la commande 'exit'.

Les autres commandes intéragissant avaec le module étant: 

-list: permet de lister les commandes en cours d'exécution en renvoyant pour chacune son identifiant, le type de commande ainsi qu'un flag indiquant s'il s'agit d'une commande asynchrone ou non.

-fg <id>: permet de remettre au premier plan une commande exécutée en tâche de fond (commande asynchrone) afin d'obtenir son résultat.

-kill <signal> <pid>: permet d'envoyer un signal à un processus de la même manière que l'outil kill.

-wait <pid> [<pid>...]: Permet d'attendre que l'un des processus passés en paramètre se termine et renvoie son code de terminaison.

-meminfo: renvoie des informations relatives à l'état de la mémoire et du swap.

-modinfo <module_name>: renvoie des informations relatives au module passé en paramètre tels que son nom, sa version, son adresse de chargement ainsi que les arguments qu'il utilise.

Note: Les commandes list, kill, meminfo et modinfo peuvent être lancées en tâche de fond (mode asynchrone) en rajoutant "&" à la fin de chaque commande dans le shell de l'outil.
Les commandes fg et wait, n'implémentent pas de mode asynchrone puisqu'elles ont pour vocation d'être bloquantes, donc synchrones.

SPÉCIFICITÉS D'IMPLÉMENTATION:


