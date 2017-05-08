KSH: Kernel shell

KSH est un petit shell permettant d'éxécuter différentes commandes:

COMMANDE

-list: permet de lister les commandes en cours dans le shell renvoie la commmande ainsi que son ID
-fg: permet de remettre au premier plan une commande éxécutée en tache de fond
-kill <id>: interrompt la commande ayant pour identifiant <id>
-wait <id>: attend la terminaison de la commande <id>
-meminfo : renvoie des informations relatives à l'état de la mémoire
-modinfo <module> renvoie des informations relatives au module <module>
note: chaque commande peut être lancée en tache de fin en rajoutant "&" derrière le nom de chaque commande.

INSTALLATION

-Patcher les sources du noyau: a la racine du kernel: "patch -p1 < swapinfo.patch"
-recompiler les sources

-lancer le module: "insmod ksh.ko"
-lancer ksh "./ksh-tool"
-lancer vos commandes

RAPPORT

Toute les commandes demandées dans le sujet sont implantées correctement et fonctionnent en mode synchrone et asynchrone
