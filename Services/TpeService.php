<?php
namespace RC\PaiementCMCICBundle\Services;

use Symfony\Component\DependencyInjection\ContainerInterface as Container;
use RC\PaiementCMCICBundle\Entity\Paiement;
use Symfony\Component\Filesystem\Filesystem;

class TpeService
{
    protected $container;
    protected $router;

    public static $hmacStr = "CtlHmac%s%s";
    public static $receipt = "version=2\ncdr=%s";

    private static $HMAC = "V1.04.sha1.php--[CtlHmac%s%s]-%s";
    private static $macok = "0";
    private static $macNotOk = "1\n";
    private static $fields = "%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*";
    private static $cgi1Fiels = "%s*%s*%s%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s";

    private $version;
    private $numero;
    private $codeSociete;
    private $langue;
    private $devise;
    private $cle;
    private $urlPaiement;
    private $serveur;

    private $urlRetour;
    private $urlOk;
    private $urlKo;

    private $finalReceipt;

    /**
     * On attribut par défaut les valeurs issus de la config
     * TpeService constructor.
     * @param Container $container
     */
    public function __construct(Container $container)
    {
        $this->container = $container;
        $this->router = $this->container->get('router');
        $kernel = $this->container->get('kernel');

        // Config du bundle
        $this->version = $this->container->getParameter('rc_paiement_cmcic.serveur')['VERSION'];

        $configClient = $this->container->getParameter('rc_paiement_cmcic.client');
        $this->numero = $configClient['TPE'];
        $this->codeSociete = $configClient['CODE_SOCIETE'];
        $this->langue = $configClient['LANGUE'];
        $this->devise = $configClient['DEVISE'];

        $configUrl = $this->container->getParameter('rc_paiement_cmcic.urls');
        $this->urlPaiement = $configUrl['URL_PAIEMENT'];

        // URL prod ou preprod en fonction de l'environnement (variable retour)
        $configServeur = $this->container->getParameter('rc_paiement_cmcic.serveur');
        if ($kernel->getEnvironment() != "prod") {
            $this->serveur = $configServeur['SERVEUR_PREPROD'];
        } else {
            $this->serveur = $configServeur['SERVEUR_PROD'];
        }

        $this->cle = $this->container->getParameter('rc_paiement_cmcic.secret')['CLE'];

        // URL de retour /paiement/{status} success | "" | error
        $this->urlRetour = $this->container->get('router')->generate(
            'paiement-retour',
            array('status' => ''),
            true
        );
        $this->urlOk = $this->container->get('router')->generate(
            'paiement-retour',
            array('status' => 'success'),
            true
        );
        $this->urlKo = $this->container->get('router')->generate(
            'paiement-retour',
            array('status' => 'error'),
            true
        );
    }

    /**
     * Permet d'initialiser l'objet paiement avec les données par défaut issue de la config ou générique
     * @param Paiement $paiement
     */
    private function handleMandatoryParameters(Paiement $paiement)
    {
        $paiement->setVersion($this->version);
        $paiement->setTPE($this->numero);
        $paiement->setDevise($this->devise);
        $paiement->setUrlRetour($this->urlRetour);
        $paiement->setUrlRetourOk($this->urlOk);
        $paiement->setUrlRetourErr($this->urlKo);
        $paiement->setLgue($this->langue);
        $paiement->setSociete($this->codeSociete);
        $paiement->setDate(date("d/m/Y:H:i:s"));
    }

    private function getUsableKey()
    {
        $hexStrKey = substr($this->cle, 0, 38);
        $hexFinal = "".substr($this->cle, 38, 2)."00";

        $cca0 = ord($hexFinal);

        if ($cca0 > 70 && $cca0 < 97) {
            $hexStrKey .= chr($cca0 - 23).substr($hexFinal, 1, 1);
        } else {
            if (substr($hexFinal, 1, 1) == "M") {
                $hexStrKey .= substr($hexFinal, 0, 1)."0";
            } else {
                $hexStrKey .= substr($hexFinal, 0, 2);
            }
        }

        return pack("H*", $hexStrKey);
    }

    private function computeHmac($sData)
    {
        return strtolower(hash_hmac("sha1", $sData, $this->getUsableKey()));
    }

    /**
     * Permet de générer la clé HMAC et de l'attribué à l'objet paiement pour la phase ALLER
     * @param Paiement $paiement
     */
    public function handleHmac(Paiement $paiement)
    {
        // Data to certify
        $fields = sprintf(
            self::$cgi1Fiels,
            $this->numero,
            $paiement->getDate(),
            $paiement->getMontantNum(),
            $paiement->getDevise(),
            $paiement->getReference(),
            $paiement->getTexteLibre(),
            $this->version,
            $this->langue,
            $this->codeSociete,
            $paiement->getMail(),
            $paiement->getNbrEch(),
            $paiement->getDateEch1(),
            $paiement->getMontantEch1(),
            $paiement->getDateEch2(),
            $paiement->getMontantEch2(),
            $paiement->getDateEch3(),
            $paiement->getMontantEch3(),
            $paiement->getDateEch4(),
            $paiement->getMontantEch4(),
            $paiement->getOptions()
        );
        $paiement->setMAC($this->computeHmac($fields));
    }

    /**
     * Permet de vérifier la signature de la réponse des serveur CMCIC pour la phase RETOUR
     * @param $parameters
     * @return bool
     */
    public function verifieSignature($parameters)
    {
        $cgiRetour = sprintf(
            self::$fields,
            $this->numero,
            $parameters["date"],
            $parameters['montant'],
            $parameters['reference'],
            $parameters['texte-libre'],
            $this->version,
            $parameters['code-retour'],
            $parameters['cvx'],
            $parameters['vld'],
            $parameters['brand'],
            $parameters['status3ds'],
            $parameters['numauto'],
            array_key_exists('motifrefus', $parameters) ? $parameters['motifrefus'] : "",
            array_key_exists('originecb', $parameters) ? $parameters['originecb'] : "",
            array_key_exists('bincb', $parameters) ? $parameters['bincb'] : "",
            array_key_exists('hpancb', $parameters) ? $parameters['hpancb'] : "",
            array_key_exists('ipclient', $parameters) ? $parameters['ipclient'] : "",
            array_key_exists('originetr', $parameters) ? $parameters['originetr'] : "",
            array_key_exists('veres', $parameters) ? $parameters['veres'] : "",
            array_key_exists('pares', $parameters) ? $parameters['pares'] : ""
        );

        if ($this->computeHmac($cgiRetour) == strtolower($parameters['MAC'])) {
            $verified = true;
        } else {
            $verified = false;
        }

        $this->handleDataTrace($parameters, $verified);
        $this->setFinalReceipt($this->handleReceipt($verified, $cgiRetour));

        return $verified;
    }

    /**
     * Dans le dossier précédent l'app root dir on met dans un dossier une trace du paiement
     * ANNEE / MOIS / time.txt avec la signature et les paramètres
     * @param $parameters
     * @param $verified
     */
    private function handleDataTrace($parameters, $verified)
    {
        $filesystem = new Filesystem();
        $rootDir = $this->container->get('kernel')->getRootDir();

        $path = sprintf('%s/../data/%s', $rootDir, date('Y\/m\/d\/'));
        $filesystem->mkdir($path);
        $content = sprintf('Signature verification : %s%s', $verified ? 'OK' : 'KO', PHP_EOL);
        foreach ($parameters as $key => $value) {
            $content .= sprintf("%s:%s%s", $key, $value, PHP_EOL);
        }
        file_put_contents(
            sprintf('%s%s.txt', $path, time()),
            $content
        );
    }

    /**
     * @param $montant float
     * @param $email string email
     * @return Paiement
     */
    public function getPaiementObjet($montant, $email)
    {
        $paiement = new Paiement();
        $this->handleMandatoryParameters($paiement);

        $paiement->setMontantNum($montant);
        $paiement->setMontant($montant.$paiement->getDevise());
        $paiement->setReference("ref".date("His"));
        $paiement->setMail($email);

        return $paiement;
    }

    /**
     * Genere le receipt qui sera renvoyé aux serveur CMCIC en tant que réponse du controlleur de retour
     * @param $verified
     * @param $cgiRetour
     * @return string
     */
    private function handleReceipt($verified, $cgiRetour)
    {
        if ($verified) {
            return self::$macok;
        } else {
            return self::$macNotOk.$cgiRetour;
        }
    }

    /**
     * @return mixed
     */
    public function getUrlPaiement()
    {
        return $this->getServeur().$this->urlPaiement;
    }

    /**
     * @return mixed
     */
    public function getServeur()
    {
        return $this->serveur;
    }

    /**
     * @return mixed
     */
    public function getFinalReceipt()
    {
        return $this->finalReceipt;
    }

    /**
     * @param mixed $finalReceipt
     */
    private function setFinalReceipt($finalReceipt)
    {
        $this->finalReceipt = $finalReceipt;
    }
}