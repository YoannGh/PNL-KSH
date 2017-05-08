KSH: Kernel shell (https://github.com/y0koz/PNL-KSH)

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

Dans le module, toutes les commandes reçues, quelles soient synchrones ou asynchrones, sont exéctuées par un worker thread. 
Après que la commande est été lancée dans un work thread, si elle était synchrone, le thread de l'outil ayant appelé l'ioctl va appeler la fonction wait_and_give_resp(cmd, give_to) qui va attendre que la 'cmd' se termine avant d'envoyer le résultat à l'espace mémoire utilisateur référencé dans la variable 'give_to'.

Lors d'un appel à la commande fg, on recherche l'identifiant de la commande passée en paramètre dans la liste des commandes en cours d'exécution. Puis on appelle aussi wait_and_give_resp(cmd, give_to), cependant cette fois la référence utilisateur 'give_to' n'est pas la même que celle à l'émission de la commande. 

Le module utilise des workqueues pour exécuter les commandes reçues de l'outil.
Si la commande à exécuter ne risque pas de se bloquer, comme la commande 'kill' par exemple, la fonction est exécutée grâce à une 'struct work_struct'.

En revanche, si la commande peut potentiellement être bloquante, c'est le cas pour 'wait' et 'modinfo', alors la fonction est exécutée grâce à une 'struct delayed_work'.
Pours la commande 'wait', si aucun processus spécifié ne sait terminé à la première exécution de la fonction 'worker_wait()', alors on programme une nouvelle exécution de cette même fonction 5 secondes plus tard.
Pour la commande 'modinfo', une demande de verrouillage du lock 'module_mutex' doit être faite afin de recherche un module, la possibilité d'être interrompu lors de l'attente de ce verrou nous permet de la même manière et relancer l'exécution de la fonction 'worker_modinfo' 1 seconde plus tard (la terminaison d'un processus étant potentiellement beaucoup plus que l'obtention d'un verrou).

Nous avons choisi de ne pas implémenter de mode asynchrone pour les commandes 'fg' et 'wait' car elles ont pour but d'être purement synchrones.

La commande 'list' affiche toujours au moins une commande: elle-même. 
 

CE QUI A ÉTÉ FAIT

Toutes les commandes demandées ont été implémentées et sont fonctionnelles.
De plus, une très grande partie des cas d'erreurs pouvant survenir ont été traités.


CE QUI N'A PAS ÉTÉ FAIT

Par manque de temps, nous n'avons malheureusement pas pu implémenter de commandes supplémentaires en plus de celles demandées.
