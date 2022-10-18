package mysql

import (
	"database/sql"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func resourceGrants() *schema.Resource {
	return &schema.Resource{
		Create: CreateGrants,
		Update: UpdateGrants,
		Read:   ReadGrants,
		Delete: DeleteGrants,
		Importer: &schema.ResourceImporter{
			State: ImportGrants,
		},

		Schema: map[string]*schema.Schema{
			"user": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},

			"role": {
				Type:          schema.TypeString,
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"user", "host"},
			},

			"host": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "localhost",
			},

			"tls_option": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "NONE",
			},

			"grants": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"database": {
							Type:     schema.TypeString,
							Required: true,
						},

						"table": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "*",
						},

						"privileges": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Set:      schema.HashString,
						},

						"roles": {
							Type:          schema.TypeSet,
							Optional:      true,
							ForceNew:      true,
							ConflictsWith: []string{"grants.0.privileges"},
							Elem:          &schema.Schema{Type: schema.TypeString},
							Set:           schema.HashString,
						},

						"grant": {
							Type:     schema.TypeBool,
							Optional: true,

							Default: false,
						},
					},
				},
			},
		},
	}
}

type SubGrantRead struct {
	Database   string
	Table      string
	Privileges *schema.Set
	Roles      *schema.Set
	Grant      bool
}

func expandGrants(p *schema.Set) []SubGrantRead {
	obj := make([]SubGrantRead, len(p.List()))

	s := p.List()
	for i := range s {
		in := s[i].(map[string]interface{})

		if v, ok := in["database"].(string); ok && len(v) > 0 {
			obj[i].Database = v
		}

		if v, ok := in["table"].(string); ok && len(v) > 0 {
			obj[i].Table = v
		}

		obj[i].Privileges = in["privileges"].(*schema.Set)

		obj[i].Roles = in["roles"].(*schema.Set)

		if v, ok := in["grant"].(bool); ok {
			obj[i].Grant = v
		}
	}

	return obj
}

func CreateGrants(d *schema.ResourceData, meta interface{}) error {
	log.Printf("[DEBUG] USING CREATE")
	db, err := meta.(*MySQLConfiguration).GetDbConn()
	if err != nil {
		return err
	}

	user := d.Get("user").(string)
	host := d.Get("host").(string)
	id := fmt.Sprintf("%s@%s", user, host)
	fs := expandGrants(d.Get("grants").(*schema.Set))
	for _, f := range fs {
		hasRoles, err := supportsRoles(db)
		if err != nil {
			return err
		}

		var (
			privilegesOrRoles string
			grantOn           string
		)

		hasPrivs := false
		rolesGranted := 0
		if f.Privileges.Len() > 0 {
			privilegesOrRoles = flattenList(f.Privileges.List(), "%s")
			hasPrivs = true
		} else if f.Roles.Len() > 0 {
			if !hasRoles {
				return fmt.Errorf("roles are only supported on MySQL 8 and above")
			}
			listOfRoles := f.Roles.List()
			rolesGranted = len(listOfRoles)
			privilegesOrRoles = flattenList(listOfRoles, "'%s'")
		} else {
			return fmt.Errorf("one of privileges or roles is required")
		}

		user := d.Get("user").(string)
		host := d.Get("host").(string)
		role := d.Get("role").(string)

		userOrRole, isRole, err := userOrRole(user, host, role, hasRoles)
		if err != nil {
			return err
		}

		database := formatDatabaseName(f.Database)

		table := formatTableName(f.Table)

		if (!isRole || hasPrivs) && rolesGranted == 0 {
			grantOn = fmt.Sprintf(" ON %s.%s", database, table)
		}

		stmtSQL := fmt.Sprintf("GRANT %s%s TO %s",
			privilegesOrRoles,
			grantOn,
			userOrRole)

		// MySQL 8+ doesn't allow REQUIRE on a GRANT statement.
		if !hasRoles && d.Get("tls_option").(string) != "" {
			stmtSQL += fmt.Sprintf(" REQUIRE %s", d.Get("tls_option").(string))
		}

		if !hasRoles && !isRole && f.Grant {
			stmtSQL += " WITH GRANT OPTION"
		}

		log.Println("[DEBUG] SQL: ", stmtSQL)
		_, err = db.Exec(stmtSQL)
		if err != nil {
			return fmt.Errorf("error running SQL (%s): %s", stmtSQL, err)
		}

	}

	d.SetId(id)

	return ReadGrants(d, meta)
}

func ReadGrants(d *schema.ResourceData, meta interface{}) error {
	log.Printf("[DEBUG] USING READ")
	db, err := meta.(*MySQLConfiguration).GetDbConn()
	if err != nil {
		return err
	}

	hasRoles, err := supportsRoles(db)
	if err != nil {
		return err
	}

	userOrRole, _, err := userOrRole(
		d.Get("user").(string),
		d.Get("host").(string),
		d.Get("role").(string),
		hasRoles)
	if err != nil {
		return err
	}

	grants, err := showGrants(db, userOrRole)

	if err != nil {
		log.Printf("[WARN] GRANT not found for %s - removing from state", userOrRole)
		d.SetId("")
		return nil
	}

	subGranter := make([](map[string]interface{}), 0)
	for _, grant := range grants {
		grantResource := make(map[string]interface{})
		grantResource["database"] = grant.Database
		grantResource["table"] = grant.Table
		grantResource["privileges"] = grant.Privileges
		grantResource["grant"] = grant.Grant
		subGranter = append(subGranter, grantResource)
	}

	d.Set("grants", subGranter)

	return nil
}

func UpdateGrants(d *schema.ResourceData, meta interface{}) error {
	log.Printf("[DEBUG] USING UPDATE")
	db, err := meta.(*MySQLConfiguration).GetDbConn()
	if err != nil {
		return err
	}

	hasRoles, err := supportsRoles(db)

	if err != nil {
		return err
	}

	userOrRole, _, err := userOrRole(
		d.Get("user").(string),
		d.Get("host").(string),
		d.Get("role").(string),
		hasRoles)

	if err != nil {
		return err
	}

	if d.HasChange("grants") {
		err = updatePrivilegesMulti(d, db, userOrRole)
		if err != nil {
			return err
		}
	}

	return nil
}

func updatePrivilegesMulti(d *schema.ResourceData, db *sql.DB, user string) error {
	oldPrivs, newPrivs := d.GetChange("grants")
	oldPrivsSet := oldPrivs.(*schema.Set)
	newPrivsSet := newPrivs.(*schema.Set)
	newPrivsList := newPrivsSet.Difference(oldPrivsSet).List()
	oldPrivsList := oldPrivsSet.Difference(newPrivsSet).List()

	log.Printf("[DEBUG] Updating privileges:\n new privileges: %+v\n old privileges: %+v", newPrivsList, oldPrivsList)

	for _, oldPriv := range oldPrivsList {
		oldPrivObj := oldPriv.(map[string]interface{})
		found := false
		for _, newPriv := range newPrivsList {
			newPrivObj := newPriv.(map[string]interface{})
			log.Printf(
				"SQL: %s, %s, %s, %s",
				formatTableName(newPrivObj["table"].(string)),
				formatTableName(oldPrivObj["table"].(string)),
				formatDatabaseName(oldPrivObj["database"].(string)),
				formatDatabaseName(newPrivObj["database"].(string)))

			if formatTableName(newPrivObj["table"].(string)) == formatTableName(oldPrivObj["table"].(string)) &&
				formatDatabaseName(oldPrivObj["database"].(string)) == formatDatabaseName(newPrivObj["database"].(string)) {

				found = true
				log.Printf("[DEBUG] %s:%s found in new, updating", newPrivObj["database"], formatTableName(newPrivObj["table"].(string)))
				err := updatePrivileges(
					newPrivObj["privileges"].(*schema.Set),
					oldPrivObj["privileges"].(*schema.Set),
					db,
					user,
					formatDatabaseName(oldPrivObj["database"].(string)),
					formatTableName(oldPrivObj["table"].(string)))

				if err != nil {
					return err
				}
				break
			}
		}
		if !found {
			log.Printf("[DEBUG] %s:%s NOT found in new, creating", formatDatabaseName(oldPrivObj["database"].(string)), formatTableName(oldPrivObj["table"].(string)))
			err := updatePrivileges(
				schema.NewSet(schema.HashString, nil),
				oldPrivObj["privileges"].(*schema.Set),
				db,
				user,
				formatDatabaseName(oldPrivObj["database"].(string)),
				formatTableName(oldPrivObj["table"].(string)))

			if err != nil {
				return err
			}
		}
	}

	for _, newPriv := range newPrivsList {
		newPrivObj := newPriv.(map[string]interface{})
		found := false
		for _, oldPriv := range oldPrivsList {
			oldPrivObj := oldPriv.(map[string]interface{})
			if formatTableName(newPrivObj["table"].(string)) == formatTableName(oldPrivObj["table"].(string)) &&
				formatDatabaseName(oldPrivObj["database"].(string)) == formatDatabaseName(newPrivObj["database"].(string)) {
				found = true
				// covered by previous iterator
				break
			}
		}
		if !found {
			err := updatePrivileges(
				newPrivObj["privileges"].(*schema.Set),
				schema.NewSet(schema.HashString, nil),
				db,
				user,
				formatDatabaseName(newPrivObj["database"].(string)),
				formatTableName(newPrivObj["table"].(string)))

			if err != nil {
				return err
			}
		}
	}

	return nil
}

func DeleteGrants(d *schema.ResourceData, meta interface{}) error {
	db, err := meta.(*MySQLConfiguration).GetDbConn()
	if err != nil {
		return err
	}

	hasRoles, err := supportsRoles(db)
	if err != nil {
		return err
	}

	userOrRole, isRole, err := userOrRole(
		d.Get("user").(string),
		d.Get("host").(string),
		d.Get("role").(string),
		hasRoles)
	if err != nil {
		return err
	}

	fs := expandGrants(d.Get("grants").(*schema.Set))
	for _, f := range fs {

		roles := f.Roles

		database := formatDatabaseName(f.Database)

		table := formatTableName(f.Table)

		privileges := f.Privileges

		var sql string
		if !isRole && len(roles.List()) == 0 {
			sql = fmt.Sprintf("REVOKE GRANT OPTION ON %s.%s FROM %s",
				database,
				table,
				userOrRole)

			log.Printf("[DEBUG] REVOKE GRANTS SQL: %s", sql)
			_, err = db.Exec(sql)

			if err != nil {
				if regexp.MustCompile("Error 1141:").MatchString(err.Error()) {
					// Error 1141: There is no such grant defined for user
					log.Printf("[WARN] error revoking GRANT (%s): %s", sql, err)
					return nil
				} else {
					return fmt.Errorf("error revoking GRANT (%s): %s", sql, err)
				}
			}
		}

		whatToRevoke := fmt.Sprintf("ALL ON %s.%s", database, table)
		if len(roles.List()) > 0 {
			whatToRevoke = flattenList(roles.List(), "'%s'")
		} else if len(privileges.List()) > 0 {
			privilegeList := flattenList(privileges.List(), "%s")
			whatToRevoke = fmt.Sprintf("%s ON %s.%s", privilegeList, database, table)
		}

		sql = fmt.Sprintf("REVOKE %s FROM %s", whatToRevoke, userOrRole)
		log.Printf("[DEBUG] REVOKE GRANTS SQL: %s", sql)
		_, err = db.Exec(sql)
		if err != nil {
			return fmt.Errorf("error revoking ALL (%s): %s", sql, err)
		}

	}

	return nil
}

func ImportGrants(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	lastSeparatorIndex := strings.LastIndex(d.Id(), "@")

	if lastSeparatorIndex <= 0 {
		return nil, fmt.Errorf("wrong ID format %s (expected USER@HOST)", d.Id())
	}

	user := d.Id()[0:lastSeparatorIndex]
	host := d.Id()[lastSeparatorIndex+1:]

	db, err := meta.(*MySQLConfiguration).GetDbConn()
	if err != nil {
		return nil, err
	}

	grants, err := showGrants(db, fmt.Sprintf("'%s'@'%s'", user, host))

	if err != nil {
		return nil, err
	}

	results := []*schema.ResourceData{restoreGrants(user, host, grants)}

	return results, nil
}

func restoreGrants(user string, host string, grants []*MySQLGrant) *schema.ResourceData {
	d := resourceGrants().Data(nil)

	id := fmt.Sprintf("%s@%s", user, host)
	d.SetId(id)

	d.Set("user", user)
	d.Set("host", host)

	grantResources := make([]interface{}, len(grants))

	for i, grant := range grants {
		grantResource := make(map[string]interface{})
		grantResource["database"] = formatDatabaseName(grant.Database)
		grantResource["table"] = formatTableName(grant.Table)
		grantResource["privileges"] = grant.Privileges
		grantResource["grant"] = grant.Grant
		grantResources[i] = grantResource
	}

	d.Set("grants", grantResources)
	d.Set("tls_option", "NONE")

	return d
}
