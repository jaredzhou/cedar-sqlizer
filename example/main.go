package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/eval"
	sqlizer "github.com/jaredzhou/cedar-sqlizer"
)

func main() {
	var p = `
	permit(
		principal,
		action == Action::Files::"list",
		resource
	)
	when {
		principal.role == "member"
	}
	when {
		resource.owner == principal  || resource.is_public == true
	};
	`
	var policy cedar.Policy
	err := policy.UnmarshalCedar([]byte(p))
	if err != nil {
		panic(err)
	}
	astPolicy := (*ast.Policy)(policy.AST())

	var es = `
		[
			{
				"uid": {"type": "User", "id": "jared"},
				"parents": [],
				"attrs": {
					"role": "member"
				}
			}
		]
	`
	var em cedar.EntityMap
	err = json.Unmarshal([]byte(es), &em)
	if err != nil {
		panic(err)
	}
	env := eval.Env{
		Entities:  em,
		Principal: cedar.NewEntityUID("User", "jared"),
		Action:    cedar.NewEntityUID("Action::Files", "list"),
		Resource:  eval.Variable("resource"),
		Context:   eval.Variable("context"),
	}
	node, keep := eval.PartialPolicyToNode(env, astPolicy)
	fmt.Println("keep", keep)
	sql, args, err := sqlizer.ToSql(node.AsIsNode(), env, fileMapper{})
	fmt.Println(sql)
	fmt.Println(args)

	selectSql := fmt.Sprintf(`SELECT * from files where %s offset 0 limit 10`, sql)
	fmt.Println(selectSql)
}

type fileMapper struct {
}

func (m fileMapper) Map(name string) (string, bool) {
	if strings.HasPrefix(name, "resource.") {
		return strings.Replace(name, "resource.", "file.", 1), true
	}
	return name, true
}
