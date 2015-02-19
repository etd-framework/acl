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
use SimpleAcl\Resource;
use SimpleAcl\Role;
use SimpleAcl\Rule;

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
     * @var Text
     */
    protected $text;

    /**
     * @var array
     */
    protected $actions;

    /**
     * @var array
     */
    protected $roles;

    /**
     * @var array
     */
    protected $rules;

    /**
     * @var array
     */
    protected $resources;

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

        // On charge les règles.
        $this->load();

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
     * Méthode pour autoriser une action.
     *
     * @param string $group_id
     * @param string $section
     * @param string $action
     *
     * @return bool True si autorisé, false sinon.
     */
    public function authorise($group_id, $section, $action) {

        // On s'assure que l'id du groupe est un string.
        $group_id = (string) $group_id;

        return $this->acl->isAllowed($group_id, $section, $action);

    }

    /**
     * Méthode pour charger les règles dans le gestionnaire ACL.
     */
    protected function load() {

        // On initialise les variables
        $roles     = $this->getRoles();
        $resources = $this->getResources();
        $sections  = $this->getActions();
        $rules     = $this->getRules();

        // On parcourt les actions par section.
        foreach ($sections as $section) {

            // Si la section a des actions.
            if (!empty($section->actions)) {

                // On récupère la ressource.
                $resource = $resources[$section->name];

                // On crée une règle pour chaque action.
                foreach ($section->actions as $action) {

                    // On récupère les autorisations des rôles pour cette action.
                    $ruleValues = $rules[$section->name]->rules->{$action->name};

                    // Et pour chaque rôle.
                    foreach ($roles as $role) {

                        // On crée une règle ACL pour le couple rôle-action.
                        $rule = new Rule($action->name);
                        $rule->setId($action->name . "-" . $role->getName());

                        // Si le rôle est présent dans la règle, il est autorisée à effectuer l'action.
                        $ruleValue = in_array($role->getName(), $ruleValues);

                        $this->acl->addRule($role, $resource, $rule, $ruleValue);

                    }

                }

            }

        }

    }

    /**
     * Méthode pour charger les rôles.
     */
    protected function getRoles() {

        if (empty($this->roles)) {

            // On initialise les variables
            $refs  = array();
            $roles = array();
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

        return $this->roles;

    }

    /**
     * Méthode pour charger les règles.
     */
    protected function getRules() {

        if (empty($this->rules)) {

            // On initialise les variables
            $refs  = array();
            $rules = array();
            $query = $this->db->getQuery(true);

            // On récupère les règles par ressources.
            $query->select('id, parent_id, resource, rules')
                  ->from('#__acl');

            $resourceRules = $this->db->setQuery($query)
                                      ->loadObjectList();

            // On construit l'arbre des règles.
            foreach ($resourceRules as $resourceRule) {

                $thisref = &$refs[$resourceRule->id];

                $thisref           = new \stdClass();
                $thisref->id       = $resourceRule->id;
                $thisref->resource = $resourceRule->resource;
                $thisref->rules    = json_decode($resourceRule->rules);

                if ($resourceRule->parent_id > 0) {
                    $refs[$resourceRule->parent_id]->addChild($thisref);
                }

                // On stocke les règles dans un tableau.
                $rules[$resourceRule->resource] = &$thisref;

            }

            $this->rules = $rules;
        }

        return $this->rules;

    }

    /**
     * Méthode pour charger les ressources.
     */
    protected function getResources() {

        if (empty($this->resources)) {

            // On initialise les variables
            $resources = array();
            $actions   = $this->getActions();

            // On parcourt les sections et on en crée des ressources.
            foreach ($actions as $section) {
                $resources[$section->name] = new Resource($section->name);
            }

            $this->resources = $resources;

        }

        return $this->resources;

    }

    /**
     * Méthode pour charger les groupes utilisateurs.
     *
     * @return mixed
     */
    protected function getUserGroups() {

        if (empty($this->usergroups)) {

            $query = $this->db->getQuery(true);

            // On récupère les groupes.
            $query->select('id, parent_id, title')
                  ->from('#__usergroups')
                  ->order('lft ASC');

            $usergroups = $this->db->setQuery($query)
                                   ->loadObjectList();

            $this->usergroups = $usergroups;

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

                    $actions = $section->xpath("action[@name]");

                    if (!empty($actions)) {

                        foreach ($actions as $action) {
                            $tmp2       = new \stdClass();
                            $tmp2->name = (string)$action['name'];
                            $tmp->actions[] = $tmp2;
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