package mysql

import (
	"fmt"
	"log"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
)

func TestAccGrants(t *testing.T) {
	dbName := "tf-test-122"
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccGrantsCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGrantsConfig_basic(dbName),
				Check: resource.ComposeTestCheckFunc(
					testAccPrivilegeExists("mysql_grants.test", "SELECT"),
					resource.TestCheckResourceAttr("mysql_grants.test", "user", fmt.Sprintf("jdoe-%s", dbName)),
					resource.TestCheckResourceAttr("mysql_grants.test", "host", "example.com"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.database", "*"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.database", "*"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.grant", "false"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.privileges.#", "1"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.privileges.666868928", "USAGE"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.roles.#", "0"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.table", "*"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.264989592.database", "tf-test-122"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.264989592.grant", "false"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.264989592.privileges.#", "2"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.264989592.privileges.1759376126", "UPDATE"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.264989592.privileges.3138006342", "SELECT"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.264989592.roles.#", "0"),
					resource.TestCheckResourceAttr("mysql_grants.test", "tls_option", "NONE"),
				),
			},
			{
				Config: testAccGrantsConfig_ssl(dbName),
				Check: resource.ComposeTestCheckFunc(
					testAccPrivilegeExists("mysql_grants.test", "SELECT"),
					resource.TestCheckResourceAttr("mysql_grants.test", "user", fmt.Sprintf("jdoe-%s", dbName)),
					resource.TestCheckResourceAttr("mysql_grants.test", "host", "example.com"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.database", "*"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.grant", "false"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.privileges.#", "1"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.privileges.666868928", "USAGE"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.roles.#", "0"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.table", "*"),
					resource.TestCheckResourceAttr("mysql_grants.test", "tls_option", "SSL"),
				),
			},
		},
	})
}

func TestAccGrants_grantOption(t *testing.T) {
	randInt := rand.Intn(100)
	db1 := "tf-test-123"
	db2 := "tf-test-124"

	config := fmt.Sprintf(`
resource "mysql_database" "db1" {
  name = "%s"
}

resource "mysql_database" "db2" {
  name = "%s"
}

resource "mysql_user" "test" {
  user     = "jdoe-%d"
  host     = "example.com"
}

resource "mysql_grants" "test_db1" {
  user       = mysql_user.test.user
  host       = mysql_user.test.host
  grants {
    database   = "*"
    privileges = ["USAGE"]
  }
  grants {
    database   = mysql_database.db1.name
    privileges = ["SELECT"]
  }
  grants {
    database   = mysql_database.db2.name
    privileges = ["SELECT"]
    grant = true
  }
}
`, db1, db2, randInt)

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccGrantsCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testAccPrivilegeExists("mysql_grants.test_db1", "SELECT"),
					resource.TestCheckResourceAttr("mysql_grants.test_db1", "user", fmt.Sprintf("jdoe-%d", randInt)),
					resource.TestCheckResourceAttr("mysql_grants.test_db1", "host", "example.com"),
					resource.TestCheckResourceAttr("mysql_grants.test_db1", "grants.3447667035.database", "tf-test-124"),
					resource.TestCheckResourceAttr("mysql_grants.test_db1", "grants.3447667035.grant", "true"),
					resource.TestCheckResourceAttr("mysql_grants.test_db1", "grants.3447667035.privileges.#", "1"),
					resource.TestCheckResourceAttr("mysql_grants.test_db1", "grants.3447667035.privileges.3138006342", "SELECT"),
					resource.TestCheckResourceAttr("mysql_grants.test_db1", "grants.3447667035.roles.#", "0"),
					resource.TestCheckResourceAttr("mysql_grants.test_db1", "grants.3447667035.table", "*"),
					resource.TestCheckResourceAttr("mysql_grants.test_db1", "grants.3526241544.database", "tf-test-123"),
					resource.TestCheckResourceAttr("mysql_grants.test_db1", "grants.3526241544.grant", "false"),
					resource.TestCheckResourceAttr("mysql_grants.test_db1", "grants.3526241544.privileges.#", "1"),
					resource.TestCheckResourceAttr("mysql_grants.test_db1", "grants.3526241544.privileges.3138006342", "SELECT"),
					resource.TestCheckResourceAttr("mysql_grants.test_db1", "grants.3526241544.roles.#", "0"),
				),
			},
		},
	})
}

func TestAccGrants_role(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	dbName := fmt.Sprintf("tf-test-%d", rand.Intn(100))
	roleName := fmt.Sprintf("TFRole%d", rand.Intn(100))
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			db, err := connectToMySQL(testAccProvider.Meta().(*MySQLConfiguration))
			if err != nil {
				return
			}

			requiredVersion, _ := version.NewVersion("8.0.0")
			currentVersion, err := serverVersion(db)
			if err != nil {
				return
			}

			if currentVersion.LessThan(requiredVersion) {
				t.Skip("Roles require MySQL 8+")
			}
		},
		Providers:    testAccProviders,
		CheckDestroy: testAccGrantCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGrantsConfig_role(dbName, roleName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("mysql_grants.test", "role", roleName),
				),
			},
		},
	})
}

func TestAccGrants_roleToUser(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	dbName := fmt.Sprintf("tf-test-%d", rand.Intn(100))
	roleName := fmt.Sprintf("TFRole%d", rand.Intn(100))
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			db, err := connectToMySQL(testAccProvider.Meta().(*MySQLConfiguration))
			if err != nil {
				return
			}

			requiredVersion, _ := version.NewVersion("8.0.0")
			currentVersion, err := serverVersion(db)
			if err != nil {
				return
			}

			if currentVersion.LessThan(requiredVersion) {
				t.Skip("Roles require MySQL 8+")
			}
		},
		Providers:    testAccProviders,
		CheckDestroy: testAccGrantsCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGrantsConfig_roleToUser(dbName, roleName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("mysql_grants.test", "user", fmt.Sprintf("jdoe-%s", dbName)),
					resource.TestCheckResourceAttr("mysql_grants.test", "host", "example.com"),
					resource.TestCheckResourceAttr("mysql_grants.test", "roles.#", "1"),
				),
			},
		},
	})
}

func TestAccGrants_update_grant(t *testing.T) {
	dbName := "up-test"
	updateConfig := fmt.Sprintf(`
	resource "mysql_database" "test" {
	  name = "%s"
	}

	resource "mysql_user" "test" {
	  user     = "jdoe-%s"
	  host     = "example.com"
	}

	resource "mysql_grants" "test" {
	  user       = "${mysql_user.test.user}"
	  host       = "${mysql_user.test.host}"
	  grants {
		database   = "*"
		privileges = ["USAGE"]
	  }
	  grants {
		database   = "${mysql_database.test.name}"
		privileges = ["UPDATE", "SELECT", "DELETE"]
	  }
	  grants {
		database   = "*"
		privileges = ["USAGE"]
	  }
	}
	`, dbName, dbName)
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccGrantsCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGrantsConfig_basic(dbName),
				Check: resource.ComposeTestCheckFunc(
					testAccDbTablePrivilegeExists("mysql_grants.test", "`up-test`.*", "SELECT"),
					testAccDbTablePrivilegeExists("mysql_grants.test", "`up-test`.*", "UPDATE"),
					testAccDbTablePrivilegeExists("mysql_grants.test", "*.*", "USAGE"),
					resource.TestCheckResourceAttr("mysql_grants.test", "user", fmt.Sprintf("jdoe-%s", dbName)),
					resource.TestCheckResourceAttr("mysql_grants.test", "host", "example.com"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.database", "*"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.grant", "false"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.privileges.#", "1"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.privileges.666868928", "USAGE"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.roles.#", "0"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2300746838.database", "up-test"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2300746838.grant", "false"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2300746838.privileges.#", "2"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2300746838.privileges.1759376126", "UPDATE"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2300746838.privileges.3138006342", "SELECT"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2300746838.roles.#", "0"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2300746838.table", "*"),
				),
			},
			{
				Config: updateConfig,
				Check: resource.ComposeTestCheckFunc(
					testAccDbTablePrivilegeExists("mysql_grants.test", "`up-test`.*", "DELETE"),
					testAccDbTablePrivilegeExists("mysql_grants.test", "`up-test`.*", "SELECT"),
					testAccDbTablePrivilegeExists("mysql_grants.test", "`up-test`.*", "UPDATE"),
					testAccDbTablePrivilegeExists("mysql_grants.test", "*.*", "USAGE"),
					resource.TestCheckResourceAttr("mysql_grants.test", "user", fmt.Sprintf("jdoe-%s", dbName)),
					resource.TestCheckResourceAttr("mysql_grants.test", "host", "example.com"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.database", "*"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.grant", "false"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.privileges.#", "1"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.privileges.666868928", "USAGE"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.roles.#", "0"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.4279720867.database", "up-test"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.4279720867.grant", "false"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.4279720867.privileges.#", "3"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.4279720867.privileges.3404380929", "DELETE"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.4279720867.privileges.1759376126", "UPDATE"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.4279720867.privileges.3138006342", "SELECT"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.4279720867.roles.#", "0"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.4279720867.table", "*"),
				),
			},
		},
	})
}

func TestAccGrants_update_revoke(t *testing.T) {
	dbName := "up-test"
	updateConfig := fmt.Sprintf(`
	resource "mysql_database" "test" {
	  name = "%s"
	}

	resource "mysql_user" "test" {
	  user     = "jdoe-%s"
	  host     = "example.com"
	}

	resource "mysql_grants" "test" {
	  user       = "${mysql_user.test.user}"
	  host       = "${mysql_user.test.host}"
	  grants {
		database   = "*"
		privileges = ["USAGE"]
	  }
	  grants {
		database   = "${mysql_database.test.name}"
		privileges = ["UPDATE"]
	  }
	}
	`, dbName, dbName)
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccGrantsCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGrantsConfig_basic(dbName),
				Check: resource.ComposeTestCheckFunc(
					testAccDbTablePrivilegeExists("mysql_grants.test", "*.*", "USAGE"),
					testAccDbTablePrivilegeExists("mysql_grants.test", "`up-test`.*", "UPDATE"),
					testAccDbTablePrivilegeExists("mysql_grants.test", "`up-test`.*", "SELECT"),
					resource.TestCheckResourceAttr("mysql_grants.test", "user", fmt.Sprintf("jdoe-%s", dbName)),
					resource.TestCheckResourceAttr("mysql_grants.test", "host", "example.com"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.database", "*"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.grant", "false"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.privileges.#", "1"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.privileges.666868928", "USAGE"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.roles.#", "0"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2300746838.database", "up-test"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2300746838.grant", "false"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2300746838.privileges.#", "2"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2300746838.privileges.1759376126", "UPDATE"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2300746838.privileges.3138006342", "SELECT"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2300746838.roles.#", "0"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2300746838.table", "*"),
				),
			},
			{
				Config: updateConfig,
				Check: resource.ComposeTestCheckFunc(
					testAccDbTablePrivilegeExists("mysql_grants.test", "*.*", "USAGE"),
					testAccDbTablePrivilegeExists("mysql_grants.test", "`up-test`.*", "UPDATE"),
					resource.TestCheckResourceAttr("mysql_grants.test", "user", fmt.Sprintf("jdoe-%s", dbName)),
					resource.TestCheckResourceAttr("mysql_grants.test", "host", "example.com"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.database", "*"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.grant", "false"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.privileges.#", "1"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.privileges.666868928", "USAGE"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.roles.#", "0"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.3170690375.database", "up-test"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.3170690375.grant", "false"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.3170690375.privileges.#", "1"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.3170690375.privileges.1759376126", "UPDATE"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.3170690375.roles.#", "0"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.3170690375.table", "*"),
				),
			},
		},
	})
}

func TestAccGrants_update_modify(t *testing.T) {
	dbName := "up-test"
	updateConfig := fmt.Sprintf(`
	resource "mysql_database" "test" {
	  name = "%s"
	}

	resource "mysql_user" "test" {
	  user     = "jdoe-%s"
	  host     = "example.com"
	}

	resource "mysql_grants" "test" {
	  user       = "${mysql_user.test.user}"
	  host       = "${mysql_user.test.host}"
	  grants {
		database   = "*"
		privileges = ["USAGE"]
	  }
	  grants {
		database   = "${mysql_database.test.name}"
		privileges = ["DELETE", "SELECT"]
	  }
	}
	`, dbName, dbName)
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccGrantsCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGrantsConfig_basic(dbName),
				Check: resource.ComposeTestCheckFunc(
					// testAccPrivilegeExists("mysql_grants.test", "SELECT"),
					// testAccPrivilegeExists("mysql_grants.test", "UPDATE"),
					// testAccPrivilegeExists("mysql_grants.test", "USAGE"),
					resource.TestCheckResourceAttr("mysql_grants.test", "user", fmt.Sprintf("jdoe-%s", dbName)),
					resource.TestCheckResourceAttr("mysql_grants.test", "host", "example.com"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.database", "*"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.grant", "false"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.privileges.#", "1"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.privileges.666868928", "USAGE"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.roles.#", "0"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2300746838.database", "up-test"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2300746838.grant", "false"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2300746838.privileges.#", "2"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2300746838.privileges.1759376126", "UPDATE"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2300746838.privileges.3138006342", "SELECT"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2300746838.roles.#", "0"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2300746838.table", "*"),
				),
			},
			{
				Config: updateConfig,
				Check: resource.ComposeTestCheckFunc(
					// testAccPrivilegeExists("mysql_grants.test", "SELECT"),
					resource.TestCheckResourceAttr("mysql_grants.test", "user", fmt.Sprintf("jdoe-%s", dbName)),
					resource.TestCheckResourceAttr("mysql_grants.test", "host", "example.com"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.database", "*"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.grant", "false"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.privileges.#", "1"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.privileges.666868928", "USAGE"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.2365372333.roles.#", "0"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.545073381.database", "up-test"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.545073381.grant", "false"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.545073381.privileges.#", "2"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.545073381.privileges.3138006342", "SELECT"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.545073381.privileges.3404380929", "DELETE"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.545073381.roles.#", "0"),
					resource.TestCheckResourceAttr("mysql_grants.test", "grants.545073381.table", "*"),
				),
			},
		},
	})
}

func testAccGrantsCheckDestroy(s *terraform.State) error {
	db, err := connectToMySQL(testAccProvider.Meta().(*MySQLConfiguration))
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "mysql_grants" {
			continue
		}

		id := strings.Split(rs.Primary.ID, ":")

		var userOrRole string
		if strings.Contains(id[0], "@") {
			parts := strings.Split(id[0], "@")
			userOrRole = fmt.Sprintf("'%s'@'%s'", parts[0], parts[1])
		} else {
			userOrRole = fmt.Sprintf("'%s'", id[0])
		}

		stmtSQL := fmt.Sprintf("SHOW GRANTS FOR %s", userOrRole)
		log.Printf("[DEBUG] SQL: %s", stmtSQL)
		rows, err := db.Query(stmtSQL)
		if err != nil {
			if mysqlErr, ok := err.(*mysql.MySQLError); ok {
				if mysqlErr.Number == nonexistingGrantErrCode {
					return nil
				}
			}

			return fmt.Errorf("error reading grant: %s", err)
		}
		defer rows.Close()

		if rows.Next() {
			return fmt.Errorf("grant still exists for: %s", userOrRole)
		}
	}
	return nil
}

func testAccGrantsConfig_basic(dbName string) string {
	return fmt.Sprintf(`
resource "mysql_database" "test" {
  name = "%s"
}

resource "mysql_user" "test" {
  user     = "jdoe-%s"
  host     = "example.com"
}

resource "mysql_grants" "test" {
  user       = "${mysql_user.test.user}"
  host       = "${mysql_user.test.host}"
  grants {
    database   = "*"
    privileges = ["USAGE"]
  }
  grants {
    database   = "${mysql_database.test.name}"
    privileges = ["UPDATE", "SELECT"]
  }
}
`, dbName, dbName)
}

func testAccGrantsConfig_ssl(dbName string) string {
	return fmt.Sprintf(`
resource "mysql_database" "test" {
  name = "%s"
}

resource "mysql_user" "test" {
  user     = "jdoe-%s"
  host     = "example.com"
}

resource "mysql_grants" "test" {
  user       = "${mysql_user.test.user}"
  host       = "${mysql_user.test.host}"
  grants {
    database   = "*"
    privileges = ["USAGE"]
  }
  grants {
    database   = "${mysql_database.test.name}"
    privileges = ["UPDATE", "SELECT"]
  }
  tls_option = "SSL"
}
`, dbName, dbName)
}

func testAccGrantsConfig_role(dbName string, roleName string) string {
	return fmt.Sprintf(`
resource "mysql_database" "test" {
  name = "%s"
}

resource "mysql_role" "test" {
  name = "%s"
}

resource "mysql_grants" "test" {
  role       = "${mysql_role.test.name}"
  grants {
    database   = "*"
    privileges = ["USAGE"]
  }
  grants {
    database   = "${mysql_database.test.name}"
    privileges = ["SELECT", "UPDATE"]
  }
}
`, dbName, roleName)
}

func testAccGrantsConfig_roleToUser(dbName string, roleName string) string {
	return fmt.Sprintf(`
resource "mysql_database" "test" {
  name = "%s"
}

resource "mysql_user" "jdoe" {
  user     = "jdoe-%s"
  host     = "example.com"
}

resource "mysql_role" "test" {
  name = "%s"
}

resource "mysql_grants" "test" {
  user     = "${mysql_user.jdoe.user}"
  host     = "${mysql_user.jdoe.host}"
  grants {
    database = "${mysql_database.test.name}"
    roles    = ["${mysql_role.test.name}"]
  }
}
`, dbName, dbName, roleName)
}

func testAccDbTablePrivilegeExists(rn string, dbAndTable string, privilege string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[rn]
		if !ok {
			return fmt.Errorf("resource not found: %s", rn)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("grant id not set")
		}

		db, err := connectToMySQL(testAccProvider.Meta().(*MySQLConfiguration))
		if err != nil {
			return err
		}

		id := strings.Split(rs.Primary.ID, ":")

		var userOrRole string
		if strings.Contains(id[0], "@") {
			parts := strings.Split(id[0], "@")
			userOrRole = fmt.Sprintf("'%s'@'%s'", parts[0], parts[1])
		} else {
			userOrRole = fmt.Sprintf("'%s'", id[0])
		}

		stmtSQL := fmt.Sprintf("SHOW GRANTS FOR %s", userOrRole)
		log.Printf("[DEBUG] SQL: %s", stmtSQL)
		rows, err := db.Query(stmtSQL)
		if err != nil {
			return fmt.Errorf("error reading grant: %s", err)
		}
		defer rows.Close()

		privilegeFound := false
		for rows.Next() {
			var grants string
			err = rows.Scan(&grants)
			if err != nil {
				return fmt.Errorf("failed to read grant for %s: %s", userOrRole, err)
			}
			if !strings.Contains(grants, dbAndTable) {
				log.Printf("[DEBUG] Skipping %s, %s", grants, dbAndTable)
				continue
			}
			log.Printf("[DEBUG] GRANTS = %s", grants)
			privIndex := strings.Index(grants, privilege)
			if privIndex != -1 {
				privilegeFound = true
				break
			}
		}

		if !privilegeFound {
			return fmt.Errorf("grant %s not found for %s", privilege, userOrRole)
		}

		return nil
	}
}
