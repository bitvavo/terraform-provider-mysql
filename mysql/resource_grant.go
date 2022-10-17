package mysql

import (
	"database/sql"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

const nonexistingGrantErrCode = 1141

type MySQLGrant struct {
	Database   string
	Table      string
	Privileges []string
	Grant      bool
}

func resourceGrant() *schema.Resource {
	return &schema.Resource{
		Create: CreateGrant,
		Update: UpdateGrant,
		Read:   ReadGrant,
		Delete: DeleteGrant,
		Importer: &schema.ResourceImporter{
			State: ImportGrant,
		},

		Schema: map[string]*schema.Schema{
			"user": {
				Type:          schema.TypeString,
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"role"},
			},

			"role": {
				Type:          schema.TypeString,
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"user", "host"},
			},

			"host": {
				Type:          schema.TypeString,
				Optional:      true,
				ForceNew:      true,
				Default:       "localhost",
				ConflictsWith: []string{"role"},
			},

			"database": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},

			"table": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
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
				ConflictsWith: []string{"privileges"},
				Elem:          &schema.Schema{Type: schema.TypeString},
				Set:           schema.HashString,
			},

			"grant": {
				Type:     schema.TypeBool,
				Optional: true,
				ForceNew: true,
				Default:  false,
			},

			"tls_option": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "NONE",
			},
		},
	}
}

func CreateGrant(d *schema.ResourceData, meta interface{}) error {
	db, err := meta.(*MySQLConfiguration).GetDbConn()
	if err != nil {
		return err
	}

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
	if attr, ok := d.GetOk("privileges"); ok {
		privilegesOrRoles = flattenList(attr.(*schema.Set).List(), "%s")
		hasPrivs = true
	} else if attr, ok := d.GetOk("roles"); ok {
		if !hasRoles {
			return fmt.Errorf("Roles are only supported on MySQL 8 and above")
		}
		listOfRoles := attr.(*schema.Set).List()
		rolesGranted = len(listOfRoles)
		privilegesOrRoles = flattenList(listOfRoles, "'%s'")
	} else {
		return fmt.Errorf("One of privileges or roles is required")
	}

	user := d.Get("user").(string)
	host := d.Get("host").(string)
	role := d.Get("role").(string)

	userOrRole, isRole, err := userOrRole(user, host, role, hasRoles)
	if err != nil {
		return err
	}

	database := formatDatabaseName(d.Get("database").(string))

	table := formatTableName(d.Get("table").(string))

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

	if !hasRoles && !isRole && d.Get("grant").(bool) {
		stmtSQL += " WITH GRANT OPTION"
	}

	log.Println("Executing statement:", stmtSQL)
	_, err = db.Exec(stmtSQL)
	if err != nil {
		return fmt.Errorf("Error running SQL (%s): %s", stmtSQL, err)
	}

	id := fmt.Sprintf("%s@%s:%s", user, host, database)
	if isRole {
		id = fmt.Sprintf("%s:%s", role, database)
	}

	d.SetId(id)

	return ReadGrant(d, meta)
}

func ReadGrant(d *schema.ResourceData, meta interface{}) error {
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

	database := d.Get("database").(string)
	table := d.Get("table").(string)

	var privileges []string
	var grantOption bool

	for _, grant := range grants {
		if grant.Database == database && grant.Table == table {
			privileges = grant.Privileges
			if grant.Grant {
				grantOption = true
			}
			break
		}
	}

	d.Set("privileges", privileges)
	d.Set("grant", grantOption)

	return nil
}

func UpdateGrant(d *schema.ResourceData, meta interface{}) error {
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

	database := formatDatabaseName(d.Get("database").(string))
	table := d.Get("table").(string)

	if d.HasChange("privileges") {
		oldPrivsIf, newPrivsIf := d.GetChange("privileges")
		oldPrivs := oldPrivsIf.(*schema.Set)
		newPrivs := newPrivsIf.(*schema.Set)
		err = updatePrivileges(oldPrivs, newPrivs, db, userOrRole, database, table)

		if err != nil {
			return err
		}
	}

	return nil
}

func updatePrivileges(newPrivs *schema.Set, oldPrivs *schema.Set, db *sql.DB, user string, database string, table string) error {
	grantIfs := newPrivs.Difference(oldPrivs).List()
	revokeIfs := oldPrivs.Difference(newPrivs).List()

	if len(revokeIfs) > 0 {
		revokes := make([]string, len(revokeIfs))

		for i, v := range revokeIfs {
			revokes[i] = v.(string)
		}

		stmtSQL := fmt.Sprintf("REVOKE %s ON %s.%s FROM %s", strings.Join(revokes, ","), database, table, user)

		log.Printf("[DEBUG] SQL: %s", stmtSQL)

		if _, err := db.Exec(stmtSQL); err != nil {
			return err
		}
	}

	if len(grantIfs) > 0 {
		grants := make([]string, len(grantIfs))

		for i, v := range grantIfs {
			grants[i] = v.(string)
		}

		stmtSQL := fmt.Sprintf("GRANT %s ON %s.%s TO %s", strings.Join(grants, ","), database, table, user)

		log.Printf("[DEBUG] SQL: %s", stmtSQL)

		if _, err := db.Exec(stmtSQL); err != nil {
			return err
		}
	}

	return nil
}

func DeleteGrant(d *schema.ResourceData, meta interface{}) error {
	db, err := meta.(*MySQLConfiguration).GetDbConn()
	if err != nil {
		return err
	}

	database := formatDatabaseName(d.Get("database").(string))

	table := formatTableName(d.Get("table").(string))

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

	roles := d.Get("roles").(*schema.Set)
	privileges := d.Get("privileges").(*schema.Set)

	var sql string
	if !isRole && len(roles.List()) == 0 {
		sql = fmt.Sprintf("REVOKE GRANT OPTION ON %s.%s FROM %s",
			database,
			table,
			userOrRole)

		log.Printf("[DEBUG] SQL: %s", sql)
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
	log.Printf("[DEBUG] SQL: %s", sql)
	_, err = db.Exec(sql)
	if err != nil {
		return fmt.Errorf("error revoking ALL (%s): %s", sql, err)
	}

	return nil
}

func ImportGrant(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
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

	results := []*schema.ResourceData{}

	for _, grant := range grants {
		results = append(results, restoreGrant(user, host, grant))
	}

	return results, nil
}

func restoreGrant(user string, host string, grant *MySQLGrant) *schema.ResourceData {
	d := resourceGrant().Data(nil)

	database := grant.Database
	id := fmt.Sprintf("%s@%s:%s", user, host, formatDatabaseName(database))
	d.SetId(id)

	d.Set("user", user)
	d.Set("host", host)
	d.Set("database", database)
	d.Set("table", grant.Table)
	d.Set("grant", grant.Grant)
	d.Set("tls_option", "NONE")
	d.Set("privileges", grant.Privileges)

	return d
}

func showGrants(db *sql.DB, user string) ([]*MySQLGrant, error) {
	grants := []*MySQLGrant{}

	stmtSQL := fmt.Sprintf("SHOW GRANTS FOR %s", user)
	rows, err := db.Query(stmtSQL)

	if err != nil {
		return nil, err
	}

	defer rows.Close()
	re := regexp.MustCompile(`^GRANT (.+) ON (.+?)\.(.+?) TO`)
	reGrant := regexp.MustCompile(`\bGRANT OPTION\b`)

	for rows.Next() {
		var rawGrant string

		err := rows.Scan(&rawGrant)

		if err != nil {
			return nil, err
		}

		m := re.FindStringSubmatch(rawGrant)

		if len(m) != 4 {
			return nil, fmt.Errorf("failed to parse grant statement: %s", rawGrant)
		}

		privileges := parsePrivileges(m[1])

		grant := &MySQLGrant{
			Database:   strings.ReplaceAll(m[2], "`", ""),
			Table:      strings.Trim(m[3], "`"),
			Privileges: privileges,
			Grant:      reGrant.MatchString(rawGrant),
		}

		grants = append(grants, grant)
	}

	return grants, nil
}
