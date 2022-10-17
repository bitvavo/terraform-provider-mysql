package mysql

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/go-version"
)

func hashSum(contents interface{}) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(contents.(string))))
}

func flattenList(list []interface{}, template string) string {
	var result []string
	for _, v := range list {
		result = append(result, fmt.Sprintf(template, v.(string)))
	}

	return strings.Join(result, ", ")
}

func formatDatabaseName(database string) string {
	if strings.Compare(database, "*") != 0 && !strings.HasSuffix(database, "`") {
		database = fmt.Sprintf("`%s`", database)

		if strings.HasPrefix(database, "`PROCEDURE ") {
			database = strings.Replace(database, "`PROCEDURE ", "PROCEDURE `", 1)
		}
	}

	return database
}

func formatTableName(table string) string {
	if table == "" || table == "*" {
		return fmt.Sprintf("*")
	}
	return fmt.Sprintf("`%s`", table)
}

func userOrRole(user string, host string, role string, hasRoles bool) (string, bool, error) {
	if len(user) > 0 && len(host) > 0 {
		return fmt.Sprintf("'%s'@'%s'", user, host), false, nil
	} else if len(role) > 0 {
		if !hasRoles {
			return "", false, fmt.Errorf("roles are only supported on MySQL 8 and above")
		}

		return fmt.Sprintf("'%s'", role), true, nil
	} else {
		return "", false, fmt.Errorf("user with host or a role is required")
	}
}

func supportsRoles(db *sql.DB) (bool, error) {
	currentVersion, err := serverVersion(db)
	if err != nil {
		return false, err
	}

	requiredVersion, _ := version.NewVersion("8.0.0")
	hasRoles := currentVersion.GreaterThan(requiredVersion)
	return hasRoles, nil
}

func parsePrivileges(privilegesString string) []string {
	rem1 := regexp.MustCompile("[A-Z]+\\ ?\\([a-zA-Z0-9_,\\ `]+\\)|[A-Z]+ [A-Z]+ [A-Z]+|[A-Z]+ [A-Z]+|[A-Z]+")
	privList := rem1.FindAllString(privilegesString, -1)

	privileges := make([]string, len(privList))

	for i, priv := range privList {
		if strings.Contains(priv, "(") {
			// Column grant sorting
			privilegeSplit := strings.Split(priv, "(")
			fmt.Printf("%+v", privilegeSplit[1])
			grantAction := strings.TrimSpace(privilegeSplit[0])
			columns := strings.Split(strings.Replace(privilegeSplit[1], ")", "", 1), ", ")
			sort.Strings(columns)
			privileges[i] = fmt.Sprintf("%s (%s)", grantAction, strings.Join(columns, ", "))
		} else {
			privileges[i] = strings.TrimSpace(priv)
		}
	}

	return privileges
}
