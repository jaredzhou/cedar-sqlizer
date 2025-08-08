package cedarsqlizer

import (
	"log/slog"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/eval"
	"github.com/jaredzhou/cedar-sqlizer/sqlizer"
	"github.com/jaredzhou/cedar-sqlizer/utils"
)

type FieldMapper = sqlizer.FieldMapper

var DefaultFieldMapper = sqlizer.DefaultFieldMapper

type AuthorizeSQLRequest struct {
	Principal cedar.EntityUID
	Action    cedar.EntityUID
	Context   cedar.Value

	FieldMapper FieldMapper
}

func AuthorizeSQL(policies cedar.PolicyIterator, entities cedar.EntityGetter, req *AuthorizeSQLRequest) (string, []interface{}, error) {
	var context types.Value
	if req.Context != nil {
		context = req.Context
	} else {
		context = eval.Variable("context")
	}
	env := eval.Env{
		Entities:  entities,
		Principal: req.Principal,
		Action:    req.Action,
		Resource:  eval.Variable("resource"),
		Context:   context,
	}

	var forbids []cedar.PolicyID
	var permits []cedar.PolicyID
	var permitsRemains = make(map[cedar.PolicyID]ast.IsNode)
	var forbidsRemains = make(map[cedar.PolicyID]ast.IsNode)
	var node ast.Node
	var permitsNode ast.Node = ast.False()
	var forbidsNode ast.Node = ast.False()
	for pid, p := range policies.All() {
		a := (*ast.Policy)(p.AST())
		satisfied, isNode, err := partial(env, a)
		if err != nil {
			return "", nil, err
		}
		if satisfied {
			if p.Effect() == cedar.Permit {
				permits = append(permits, pid)
			} else {
				forbids = append(forbids, pid)
			}
		}
		if isNode != nil {
			if p.Effect() == cedar.Permit {
				permitsRemains[pid] = isNode
			} else {
				forbidsRemains[pid] = isNode
			}
		}
	}

	if len(forbids) > 0 {
		node = ast.False()
		for _, pid := range forbids {
			slog.Debug("forbid policy", "pid", pid)
		}
	} else if len(permits) > 0 {
		node = ast.True()
		for _, pid := range permits {
			slog.Debug("permit policy", "pid", pid)
		}
	} else {
		node = ast.True()
		// permitsreamin determine every row that satisfies any of the permits
		if len(permitsRemains) > 0 {
			for _, isNode := range permitsRemains {
				if permitsNode.AsIsNode() == nil {
					permitsNode = ast.NewNode(isNode)
				} else {
					permitsNode = permitsNode.Or(ast.NewNode(isNode))
				}
			}
		}
		if permitsNode.AsIsNode() != nil {
			node = node.And(permitsNode)
		}

		// forbidsRemains determine rows that satisfies any of the forbids
		if len(forbidsRemains) > 0 {
			for _, isNode := range forbidsRemains {
				if forbidsNode.AsIsNode() == nil {
					forbidsNode = ast.NewNode(isNode)
				} else {
					forbidsNode = forbidsNode.Or(ast.NewNode(isNode))

				}
			}
		}

		// the result row should satisfy any of the permits
		// and not satisfy any of the forbids
		if forbidsNode.AsIsNode() != nil {
			node = node.And(ast.Not(forbidsNode))
		}

	}

	var mapper FieldMapper
	if req.FieldMapper != nil {
		mapper = req.FieldMapper
	} else {
		mapper = DefaultFieldMapper
	}
	sql, args, err := sqlizer.ToSql(node.AsIsNode(), env, mapper)
	return sql, args, err
}

func partial(env eval.Env, p *ast.Policy) (satisfied bool, isNode ast.IsNode, err error) {
	p, keep := eval.PartialPolicy(env, p)
	if !keep {
		return false, nil, nil
	}
	node := eval.PolicyToNode(p)
	// if it is NodeValue it must be a true value , otherwise it is not keep
	// or it is a variable(essentially a EntityUID with type variableEntityType) so it is possible to be true in the future
	if valNode, ok := node.AsIsNode().(ast.NodeValue); ok {
		if _, ok := eval.ToVariable(valNode.Value); ok {
			return false, node.AsIsNode(), nil
		}
		boolVal, err := utils.ValueToType[cedar.Boolean](valNode.Value)
		if err != nil {
			return false, nil, err
		}
		return bool(boolVal), nil, nil
	}
	// return the remian node to further sqlize
	return false, node.AsIsNode(), nil
}
