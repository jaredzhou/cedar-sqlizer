package utils

import (
	"fmt"
	"strings"

	"github.com/cedar-policy/cedar-go/x/exp/ast"
)

func NString(node ast.IsNode) string {
	if node == nil {
		return "nil node"
	}
	switch n := node.(type) {
	case ast.NodeTypeAccess:
		return fmt.Sprintf("%s.%s", NString(n.Arg), n.Value)
	case ast.NodeValue:
		return n.Value.String()
	case ast.NodeTypeNot:
		return fmt.Sprintf("!%s", NString(n.Arg))
	case ast.NodeTypeVariable:
		return n.Name.String()
	case ast.NodeTypeIn:
		return fmt.Sprintf("%s IN %s", NString(n.Left), NString(n.Right))
	case ast.NodeTypeAnd:
		return fmt.Sprintf("%s AND %s", NString(n.Left), NString(n.Right))
	case ast.NodeTypeOr:
		return fmt.Sprintf("(%s OR %s)", NString(n.Left), NString(n.Right))
	case ast.NodeTypeEquals:
		return fmt.Sprintf("%s = %s", NString(n.Left), NString(n.Right))
	case ast.NodeTypeNotEquals:
		return fmt.Sprintf("%s != %s", NString(n.Left), NString(n.Right))
	case ast.NodeTypeGreaterThan:
		return fmt.Sprintf("%s > %s", NString(n.Left), NString(n.Right))
	case ast.NodeTypeIsEmpty:
		return fmt.Sprintf("%s.isEmpty() ", NString(n.Arg))
	case ast.NodeTypeExtensionCall:
		args := make([]string, len(n.Args))
		for i, arg := range n.Args {
			args[i] = NString(arg)
		}
		return fmt.Sprintf("%s(%s)", n.Name, strings.Join(args, ", "))
	case ast.NodeTypeHas:
		return fmt.Sprintf("%s has %s", NString(n.Arg), n.Value)
	case ast.NodeTypeGetTag:
		return fmt.Sprintf("%s.getTag(%s)", NString(n.Left), NString(n.Right))
	case ast.NodeTypeLike:
		return fmt.Sprintf("%s like %s", NString(n.Arg), n.Value)
	case ast.NodeTypeIfThenElse:
		return fmt.Sprintf("if %s then %s else %s", NString(n.If), NString(n.Then), NString(n.Else))
	case ast.NodeTypeIs:
		return fmt.Sprintf("%s is %s", NString(n.Left), n.EntityType)
	case ast.NodeTypeIsIn:
		return fmt.Sprintf("%s in %s", NString(n.Left), NString(n.Entity))
	case ast.NodeTypeNegate:
		return fmt.Sprintf("!%s", NString(n.Arg))
	case ast.NodeTypeRecord:
		elements := make([]string, len(n.Elements))
		for i, element := range n.Elements {
			elements[i] = fmt.Sprintf("%s: %s", element.Key, NString(element.Value))
		}
		return fmt.Sprintf("{%s}", strings.Join(elements, ", "))
	case ast.NodeTypeSet:
		elements := make([]string, len(n.Elements))
		for i, element := range n.Elements {
			elements[i] = fmt.Sprintf("%s", NString(element))
		}
		return fmt.Sprintf("{%s}", strings.Join(elements, ", "))
	case ast.NodeTypeContains:
		return fmt.Sprintf("%s contains %s", NString(n.Left), NString(n.Right))
	case ast.NodeTypeContainsAny:
		return fmt.Sprintf("%s containsAny %s", NString(n.Left), NString(n.Right))
	case ast.NodeTypeContainsAll:
		return fmt.Sprintf("%s containsAll %s", NString(n.Left), NString(n.Right))

	default:
		return fmt.Sprintf("NString unsupported node type: %T", n)
	}
}
