# Bundle de paiement CM & CIC 

Ce bundle permet une implementation rapide et simple des solutions de paiement en ligne des banques Crédit Mutuel et Crédit Industriel et Commercial
Attention ce bundle est actuellement en phase de développement mais il peut tout de même être utilisé en production en prennant en compte certaines précautions.

Ce bundle s'appuit sur le code PHP fournit par les banques. Le but est de founir des services et des controllers facilement utilisable dans Symfony 2.

Ci-dessous les documentations du TPE.

[DOC GENERALE](https://www.cmcicpaiement.fr/fr/info/documentations/CM-CIC_paiement_documentation_generale_v3_0.pdf)

[DOC TECHNIQUE](https://www.cmcicpaiement.fr/fr/info/documentations/CM-CIC_paiement_documentation_technique_v3_0.pdf)

### TODO

- [ ] Effectuer un test d'intégration du bundle
- [ ] Effectuer les test unitaires et fonctionnels
- [ ] Mise en place sur [TRAVIS-CI](https://travis-ci.org/)
- [ ] Revoir les pré-requis du `composer.json`
- [ ] Test du paiement par échelon

## Mise en place

### Ajout grâce à composer

Dans la console :

    composer require rollincode/paiementcmcic-bundle
    
### Ajout dans l'appKernel

Dans `app/AppKernel.php` :
    
    ...
    new RC\PaiementCMCICBundle\RCPaiementCMCICBundle(),
    ...

### Ajout du routing

Dans `app/config/routing.yml` :

    ...
    rc_paiement_cmcic:
        resource: "@RCPaiementCMCICBundle/Controller/"
        type:     annotation
        prefix:   /mon-prefix
    ...
    
### Configuration

Dans `app/config/services.yml` et adaptez là avec les identifiants fournis par la banque.

    rc_paiement_cmcic:
        client:
            CODE_SOCIETE: "CODE_SOCIETE"
            TPE: "NUMERO_TPE"
            LANGUE: "FR"
            DEVISE: "EUR"
    
        serveur:
            # URL pour la prod ex: "https://ssl.paiement.cic-banques.fr/"
            SERVEUR_PROD: "MON_URL"
            # URL pour la préprod ex: "https://ssl.paiement.cic-banques.fr/test/"
            SERVEUR_PREPROD: "MON_URL"
            VERSION: "3.0"
    
        urls:
            URL_PAIEMENT: "paiement.cgi"
    
        secret:
            CLE: "MA_CLE_SECRETE"

### Utilisation

Le bundle fournit 2 services et 1 controller.

Le service `TpeService` disponible via `$this->container->get('rc.paiementcmcic_tpe');` permet d'utiliser les méthodes relatives à l'initialisation du formulaire.

L'objet `Paiement` disponible via la méthode du service `getPaiementObjet($montant, $email)` permet donc de peupler le formulaire avec un objet prêt à l'emploi.

Le service `rc.paiementcmcic_logic_tpe` est un exemple de service devant être implanté pour le traitement métier (mise à jour base de données, etc).

Ce service est appelé lorsque les serveurs CMCIC interrogent le serveur de l'application afin de lui informer le statut du paiement effectuer.

Il faudra donc adapter les cas de chaque retour (succès, erreur, etc.)

ATTENTION c'est seulement dans ce cas-là qu'il faudra implanter la logique métier cêté commerçant, en effet, c'est seulement à ce moment qu'on est sûr du résultat du paiement.

Lors de la phase retour effectué par les serveurs CMCIC, on créer une architecture de dossier qui stock les paramètres retour et la verification de signature.
Par défaut ce dossier est `DOSSIER_APPLICATION/data/ANNEE/MOIS/TIME.txt`
