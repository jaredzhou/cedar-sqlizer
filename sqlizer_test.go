package sqlizer

import (
	"testing"

	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/eval"
)

func TestToSql(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		node   ast.Node
		env    eval.Env
		mapper FieldMapper
		want   string
		args   []interface{}
	}{
		{
			name: "empty",
			node: ast.Context().Access("foo").IsEmpty(),
			env: eval.Env{
				Context: eval.Variable("context"),
			},
			mapper: defaultFieldMapper{},
			want:   "context.foo IS NULL",
			args:   nil,
		},
		{
			name: "equal",
			node: ast.Context().Access("foo").Equal(ast.String("bar")),
			env: eval.Env{
				Context: eval.Variable("context"),
			},
			mapper: defaultFieldMapper{},
			want:   "context.foo = ?",
			args:   []interface{}{"bar"},
		},
		{
			name: "not equal",
			node: ast.Context().Access("foo").NotEqual(ast.String("bar")),
			env: eval.Env{
				Context: eval.Variable("context"),
			},
			mapper: defaultFieldMapper{},
			want:   "context.foo != ?",
			args:   []interface{}{"bar"},
		},
		// and
		{
			name: "and",
			node: ast.Context().Access("foo").Equal(ast.String("bar")).And(ast.Context().Access("baz").Equal(ast.Long(50))),
			env: eval.Env{
				Context: eval.Variable("context"),
			},
			mapper: defaultFieldMapper{},
			want:   "(context.foo = ? AND context.baz = ?)",
			args:   []interface{}{"bar", int64(50)},
		},
		// or
		{
			name: "or",
			node: ast.Context().Access("foo").Equal(ast.String("bar")).Or(ast.Context().Access("baz").Equal(ast.Long(50))),
			env: eval.Env{
				Context: eval.Variable("context"),
			},
			mapper: defaultFieldMapper{},
			want:   "(context.foo = ? OR context.baz = ?)",
			args:   []interface{}{"bar", int64(50)},
		},
		{
			name: "equal entity",
			node: ast.Resource().Equal(ast.EntityUID("doc", "123")),
			env: eval.Env{
				Context:  eval.Variable("context"),
				Resource: eval.Variable("resource"),
			},
			mapper: defaultFieldMapper{},
			want:   "resource.id = ?",
			args:   []interface{}{"123"},
		},
		{
			name: "resource complex",
			node: ast.Resource().Access("owner").Equal(ast.Principal()).Or(ast.Resource().Access("is_public").Equal(ast.Boolean(true))),
			env: eval.Env{
				Context:   eval.Variable("context"),
				Resource:  eval.Variable("resource"),
				Principal: types.NewEntityUID("user", "123"),
			},
			mapper: defaultFieldMapper{},
			want:   "(resource.owner = ? OR resource.is_public = ?)",
			args:   []interface{}{"123", true},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, args, err := ToSql(test.node.AsIsNode(), test.env, test.mapper)
			if err != nil {
				t.Fatalf("ToSql(%v) = %v err: %v", test.node, test.want, err)
			}
			if got != test.want {
				t.Fatalf("ToSql(%v) = %v, want %v", test.node, got, test.want)
			}
			if len(test.args) > 0 {
				if len(args) != len(test.args) {
					t.Fatalf("ToSql(%v) = %v, want %v", test.node, args, test.args)
				}
				for i, arg := range test.args {
					if args[i] != arg {
						t.Fatalf("ToSql(%v) = %v, want %v", test.node, args[i], arg)
					}
				}
			}
		})
	}
}

func TestConj(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		expr Sqlizer
		want string
	}{
		{
			name: "and",
			expr: AndExpr(
				Expr("1 = 1"),
				Expr("2 = 2"),
			),
			want: "(1 = 1 AND 2 = 2)",
		},
		{
			name: "or",
			expr: OrExpr(
				Expr("1 = 1"),
				Expr("2 = 2"),
			),
			want: "(1 = 1 OR 2 = 2)",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, _, err := test.expr.ToSql()
			if err != nil {
				t.Fatalf("ToSql(%v) = %v err: %v", test.expr, test.want, err)
			}
			if got != test.want {
				t.Fatalf("ToSql(%v) = %v, want %v", test.expr, got, test.want)
			}
		})
	}
}
