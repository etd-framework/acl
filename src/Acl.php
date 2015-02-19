<?php
/**
 * Part of the ETD Framework ACL Package
 *
 * @copyright Copyright (C) 2015 ETD Solutions, SARL Etudoo. Tous droits réservés.
 * @license   Apache License 2.0; see LICENSE
 * @author    ETD Solutions http://etd-solutions.com
 */

namespace EtdSolutions\Acl;

use Joomla\Database\DatabaseDriver;
use Joomla\Language\Text;
use SimpleAcl\Acl as SimpleAcl;
use SimpleAcl\Role;

/**
 * Classe de gestion des droits utilisateurs.
 */
class Acl {

    /**
     * @var DatabaseDriver Le gestionnaire de la base de données.
     */
    protected $db;

    /**
     * @var SimpleAcl Le gestionnaire des contrôles d'accès.
     */
    protected $acl;

    /**
     * @var Text Le gestio
     */
    protected $text;

    /**
     * @var
     */
    protected $actions;

    /**
     * @var
     */
    protected $roles;

    /**
     * @var
     */
    protected $usergroups;

    /**
     * @var  Acl  L'instance de la classe de gestion.
     */
    private static $instance;

    /**
     * Constructeur
     *
     * @param DatabaseDriver $db Le gestionnaire de la base de données.
     * @param Text           $text
     */
    public function __construct(DatabaseDriver $db, Text $text) {

        // Paramètres
        $this->db   = $db;
        $this->text = $text;

        // On instancie le gestionnaire des contrôles d'accès.
        $this->acl = new SimpleAcl();

        // On charge les rôles.
        $this->loadRoles();

        // On charge les ressources.
        $this->loadResources();

        // On crée les règles.
        $this->loadRules();

    }

    /**
     * Retourne l'objet global Acl, en le créant seulement il n'existe pas déjà.
     *
     * @param DatabaseDriver $db Le gestionnaire de base de données.
     * @param Text           $text
     *
     * @return  Acl  L'objet Acl.
     */
    public static function getInstance($db = null, $text = null) {

        if (empty(self::$instance)) {

            if (is_null($db) || is_null($text)) {
                throw new \RuntimeException('Empty params');
            }

            self::$instance = new Acl($db, $text);
        }

        return self::$instance;
    }

    /**
     * Méthode pour charger les rôles dans le gestionnaire ACL.
     *
     * Les rôles sont représentés par les groupes utilisateurs.
     */
    public function loadRoles() {

        // On initialise les variables;
        $refs       = array();
        $roles       = array();
        $usergroups = $this->getUserGroups();

        // On construit l'arbre des rôles.
        foreach ($usergroups as $usergroup) {

            $thisref = &$refs[$usergroup->id];
            $thisref = new Role($usergroup->id);

            if ($usergroup->parent_id > 0) {
                $refs[$usergroup->parent_id]->addChild($thisref);
            }

            // On stocke les rôles dans un tableau pour leur associer les règles plus tard.
            $roles[$usergroup->id] = &$thisref;

        }

        $this->roles = $roles;

    }

    /**
     * Méthode pour charger les ressources dans le gestionnaire ACL.
     */
    public function loadResources() {

    }

    /**
     * Méthode pour charger les règles dans le gestionnaire ACL.
     */
    public function loadRules() {

    }

    protected function getUserGroups() {

        if (empty($usergroups)) {

            $query = $this->db->getQuery(true);

            // On récupère les groupes.
            $query->select('id, parent_id, title')
                  ->from('#__usergroups')
                  ->order('lft ASC');

            $usergroups = $this->db->setQuery($query)
                                   ->loadObjectList();

            $this->usergroups = $usergroups;

            /* $refs = array();
             $list = array();

             foreach ($usergroups as $usergroup) {

                 $thisref = &$refs[$usergroup->id];

                 $thisref            = new \stdClass();
                 $thisref->id        = $usergroup->id;
                 $thisref->parent_id = $usergroup->parent_id;
                 $thisref->name      = $usergroup->title;

                 if ($usergroup->parent_id == 0) {
                     $list[$usergroup->id] = &$thisref;
                 } else {
                     $refs[$usergroup->parent_id]->children[$usergroup->id] = &$thisref;
                 }

             }

             $this->usergroups = $list;*/

        }

        return $this->usergroups;

    }

    /**
     * Méthode pour récupérer les actions possibles dans l'application.
     *
     * @return array
     */
    protected function getActions() {

        if (empty($this->actions)) {

            // On charge les droits depuis le XML.
            $data = simplexml_load_file(JPATH_ROOT . "/rights.xml");

            // On contrôle que les données sont bien chargées.
            if ((!($data instanceof \SimpleXMLElement)) && (!is_string($data))) {
                throw new \RuntimeException($this->text->translate('APP_ERROR_RIGHTS_NOT_LOADED'));
            }

            // On initialise les actions.
            $result = array();

            // On récupère les sections.
            $sections = $data->xpath("/rights/section");

            if (!empty($sections)) {

                foreach ($sections as $section) {

                    $tmp          = new \stdClass();
                    $tmp->name    = (string)$section['name'];
                    $tmp->actions = array();

                    $actions = $section->xpath("action[@name][@title][@description]");

                    if (!empty($actions)) {

                        foreach ($actions as $action) {
                            $tmp2       = new \stdClass();
                            $tmp2->name = (string)$action['name'];
                        }

                        $result[] = $tmp;
                    }

                }

            }

            $this->actions = $result;

        }

        return $this->actions;

    }

}